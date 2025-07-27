/*
 * ESP-IDF OTA Firmware Update Client
 *
 * This application connects to an Ethernet network and fetches a firmware update
 * from a custom HTTP server (the provided Python Flask app).
 *
 * It is designed for the Espressif IoT Development Framework (ESP-IDF).
 *
 * HOW IT WORKS:
 * 1. Initializes NVS (Non-Volatile Storage), which is required for network configurations.
 * 2. Initializes and connects to the specified Ethernet network with a static IP.
 * 3. Creates a FreeRTOS task that periodically checks for updates.
 * 4. This task makes an HTTP GET request to http://<SERVER_IP>:5000/firmware.
 * 5. It reads the JSON response, which contains the firmware as a Base64 string.
 * 6. It uses the cJSON library to parse the response and extract the Base64 data.
 * 7. It uses the mbedTLS library (included in ESP-IDF) to decode the Base64 string
 * back into a binary firmware image.
 * 8. It performs the OTA update using the native ESP-IDF OTA functions.
 * 9. On a successful update, it restarts the device to boot the new firmware.
 *
 * PROJECT CONFIGURATION (menuconfig):
 * - You must enable the cJSON library:
 * Component config -> JSON Common -> Support cJSON in project
 * - You must enable Ethernet and select your PHY (e.g., LAN8720):
 * Component config -> Ethernet -> Ethernet driver
 * Component config -> Ethernet -> Ethernet PHY -> LAN8720
 * - Ensure HTTP Client and OTA libraries are enabled (they are by default).
 *
 * HOW TO USE:
 * 1. Create a new ESP-IDF project.
 * 2. Replace the contents of `main/main.cpp` with this code.
 * 3. Update the `SERVER_IP` definition below to your PC's IP address.
 * 4. Build and flash the project to your ESP32: `idf.py build flash monitor`
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "cJSON.h"
#include "mbedtls/base64.h"
#include "esp_eth.h"
#include "driver/gpio.h"
#include "esp_netif.h"
// FIX: Corrected typo from 'esp_eth_phy.he' to 'esp_eth_phy.h'
#include "esp_eth_phy.h"
#include "esp_eth_phy_lan8720.h" // Required for esp_eth_phy_new_lan8720

// Define missing PHY address macro if not defined by menuconfig
// This macro is typically set in sdkconfig via menuconfig -> Component config -> Ethernet -> Ethernet PHY -> PHY address
#ifndef CONFIG_ETH_PHY_ADDR
#define CONFIG_ETH_PHY_ADDR 0 // Default PHY address for LAN8720
#endif

// Define the PHY reset GPIO if not defined in menuconfig.
// This macro is typically set in sdkconfig via menuconfig -> Component config -> Ethernet -> Ethernet PHY -> PHY_RST_GPIO
#ifndef CONFIG_ETH_PHY_RST_GPIO
#define CONFIG_ETH_PHY_RST_GPIO -1 // Set to -1 if not used, or replace with your reset GPIO number (e.g., 5, 16, 17)
#endif

// --- Configuration ---
// IMPORTANT: Replace with your PC's IP address (from ipconfig/ifconfig)
#define SERVER_IP           "XXX.XXX.XXX.XXX"
#define SERVER_PORT         "XXXX"
#define FIRMWARE_URL        "http://" SERVER_IP ":" SERVER_PORT "/firmware"

// Set ESP32 static IP and MAC
#define ESP32_STATIC_IP     "XXX.XXX.XXX.XXX"
#define ESP32_STATIC_GW     "XXX.XXX.XXX.XXX"
#define ESP32_STATIC_NETMASK "XXX.XXX.XXX.XXX"
#define ESP32_ETH_MAC       {0x02, 0x00, 0x00, 0x12, 0x34, 0x56} // Example MAC address

#define OTA_CHECK_INTERVAL_MS (30 * 1000) // Check every 30 seconds

// --- Globals ---
static const char *TAG = "OTA_CLIENT";
#define OTA_HTTP_BUFFER_SIZE 1024 // Buffer size for HTTP response

// Event group to signal when Ethernet is connected and has an IP address
static EventGroupHandle_t s_eth_event_group;
#define ETH_CONNECTED_BIT BIT0 // Bit to set when Ethernet is connected and has IP
#define ETH_FAIL_BIT      BIT1 // Bit to set if Ethernet connection fails (not used in current logic, but good for future error handling)

// --- Ethernet Event Handler ---
// This function handles various Ethernet and IP events.
static void eth_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data) {
    if (event_base == ETH_EVENT && event_id == ETHERNET_EVENT_CONNECTED) {
        ESP_LOGI(TAG, "Ethernet Link Up");
    } else if (event_base == ETH_EVENT && event_id == ETHERNET_EVENT_DISCONNECTED) {
        ESP_LOGI(TAG, "Ethernet Link Down");
    } else if (event_base == ETH_EVENT && event_id == ETHERNET_EVENT_START) {
        ESP_LOGI(TAG, "Ethernet Started");
    } else if (event_base == ETH_EVENT && event_id == ETHERNET_EVENT_STOP) {
        ESP_LOGI(TAG, "Ethernet Stopped");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        // When the ESP32 gets an IP address via Ethernet, log it and set the connected bit.
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP address:" IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_eth_event_group, ETH_CONNECTED_BIT);
    }
}

// --- Ethernet Initialization ---
// This function initializes the ESP32's Ethernet interface with a static IP.
void eth_init(void) {
    // Create an event group to synchronize Ethernet connection status.
    s_eth_event_group = xEventGroupCreate();

    // Initialize TCP/IP adapter (required for network interfaces).
    ESP_ERROR_CHECK(esp_netif_init());
    // Create the default event loop for system events.
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Configure and create a new Ethernet network interface.
    esp_netif_inherent_config_t esp_netif_inherent_config = ESP_NETIF_INHERENT_DEFAULT_ETH();
    esp_netif_inherent_config.if_desc = "eth";
    esp_netif_inherent_config.route_prio = 30; // Set routing priority
    esp_netif_config_t netif_cfg = {
        .base = &esp_netif_inherent_config,
        .driver = NULL, // Driver will be attached later
        .stack = NULL
    };
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);

    // Set static IP address for the Ethernet interface.
    esp_netif_ip_info_t ip_info;
    ip4addr_aton(ESP32_STATIC_IP, (ip4_addr_t *)&ip_info.ip);
    ip4addr_aton(ESP32_STATIC_GW, (ip4_addr_t *)&ip_info.gw);
    ip4addr_aton(ESP32_STATIC_NETMASK, (ip4_addr_t *)&ip_info.netmask);
    ESP_ERROR_CHECK(esp_netif_dhcpc_stop(eth_netif)); // Stop DHCP client
    ESP_ERROR_CHECK(esp_netif_set_ip_info(eth_netif, &ip_info)); // Set static IP info

    // Configure Ethernet MAC and PHY.
    // Use default configurations as a starting point.
    eth_esp32_emac_config_t mac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

    // Set SMI MDC and MDIO GPIOs in the PHY config (for LAN8720).
    // These GPIOs are typically defined in menuconfig, but can be set here if needed.
    // Example: phy_config.smi_mdc_gpio_num = 23; phy_config.smi_mdio_gpio_num = 18;
    phy_config.phy_addr = CONFIG_ETH_PHY_ADDR; // PHY address from menuconfig or default
    phy_config.reset_gpio_num = CONFIG_ETH_PHY_RST_GPIO; // PHY reset GPIO from menuconfig or default

    // Set custom MAC address.
    uint8_t custom_mac[6] = ESP32_ETH_MAC;

    // Configure ESP32 GPIOs for Ethernet.
    eth_esp32_gpio_config_t gpio_config = ETH_ESP32_DEFAULT_GPIO_CONFIG();
    // Create new Ethernet MAC and PHY instances.
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&mac_config, &gpio_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan8720(&phy_config); // Use LAN8720 PHY

    // Combine MAC and PHY into a complete Ethernet configuration.
    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    // Install the Ethernet driver.
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));
    // Set custom MAC address after driver installation.
    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_MAC_ADDR, custom_mac));
    // Attach the network interface to the Ethernet driver.
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, eth_handle));

    // Register event handlers for Ethernet and IP events.
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL));

    // Start the Ethernet driver.
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    // Wait for the Ethernet connection to be established and an IP address to be obtained.
    ESP_LOGI(TAG, "Waiting for Ethernet connection...");
    EventBits_t bits = xEventGroupWaitBits(s_eth_event_group,
                                           ETH_CONNECTED_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           portMAX_DELAY); // Wait indefinitely

    if (bits & ETH_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Ethernet Connected Successfully");
    } else {
        ESP_LOGE(TAG, "Ethernet Connection Failed");
        // In a real application, you might want to retry or handle this error more gracefully.
    }
}

// --- HTTP Event Handler for OTA ---
// This handler is called for various HTTP client events.
// For OTA, we mainly care about successful connection and data reception.
esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            // This event is triggered when HTTP data is received.
            // For OTA, the entire firmware is expected in a single JSON response,
            // so we're not writing directly to OTA partition here.
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            break;
    }
    return ESP_OK;
}

// --- Main OTA Update Task ---
// This FreeRTOS task periodically checks for new firmware updates.
void ota_update_task(void *pvParameter) {
    ESP_LOGI(TAG, "Starting OTA update task...");

    esp_http_client_config_t config = {
        .url = FIRMWARE_URL,
        .event_handler = _http_event_handler,
        .keep_alive_enable = true, // Keep HTTP connection alive if possible
    };

    while (1) {
        ESP_LOGI(TAG, "Checking for update from %s", FIRMWARE_URL);

        esp_http_client_handle_t client = esp_http_client_init(&config);
        if (client == NULL) {
            ESP_LOGE(TAG, "Failed to initialize HTTP client");
            vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
            continue;
        }

        esp_err_t err = esp_http_client_perform(client); // Perform the HTTP GET request

        if (err == ESP_OK) {
            int status_code = esp_http_client_get_status_code(client);
            ESP_LOGI(TAG, "HTTP GET Status = %d", status_code);

            if (status_code == 200) {
                // --- Process the response ---
                // Get the total content length from the HTTP header.
                int content_length = esp_http_client_get_content_length(client);
                if (content_length <= 0) {
                    ESP_LOGE(TAG, "Invalid content length received from server.");
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }

                // Allocate buffer large enough for the entire JSON response.
                // Add 1 for null terminator.
                char *response_buffer = (char *)malloc(content_length + 1);
                if (response_buffer == NULL) {
                    ESP_LOGE(TAG, "Failed to allocate response buffer.");
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }

                // Read the entire response data into the buffer.
                int total_read_len = esp_http_client_read(client, response_buffer, content_length);
                if (total_read_len != content_length) {
                    ESP_LOGE(TAG, "Failed to read full response data. Expected %d, got %d", content_length, total_read_len);
                    free(response_buffer);
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }
                response_buffer[total_read_len] = '\0'; // Null-terminate the string

                // --- Parse JSON ---
                cJSON *root = cJSON_Parse(response_buffer);
                if (root == NULL) {
                    const char *error_ptr = cJSON_GetErrorPtr();
                    if (error_ptr != NULL) {
                        ESP_LOGE(TAG, "Failed to parse JSON response before: %s", error_ptr);
                    } else {
                        ESP_LOGE(TAG, "Failed to parse JSON response (unknown error)");
                    }
                    free(response_buffer);
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }

                cJSON *firmware_b64_json = cJSON_GetObjectItem(root, "bin_content_base64");
                if (!cJSON_IsString(firmware_b64_json) || (firmware_b64_json->valuestring == NULL)) {
                    ESP_LOGE(TAG, "JSON does not contain 'bin_content_base64' string or it's empty.");
                    cJSON_Delete(root);
                    free(response_buffer);
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }

                char *firmware_b64 = firmware_b64_json->valuestring;
                ESP_LOGI(TAG, "Successfully parsed JSON and got Base64 data.");

                // --- Decode Base64 and Perform OTA ---
                size_t b64_len = strlen(firmware_b64);
                size_t decoded_len = 0;
                // First call to mbedtls_base64_decode with NULL output buffer to get required size.
                // This is safer to avoid buffer overflows.
                if (mbedtls_base64_decode(NULL, 0, &decoded_len, (const unsigned char *)firmware_b64, b64_len) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
                    ESP_LOGE(TAG, "Failed to determine decoded size for Base64 firmware.");
                    cJSON_Delete(root);
                    free(response_buffer);
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }

                unsigned char *decoded_firmware = (unsigned char *)malloc(decoded_len);
                if (decoded_firmware == NULL) {
                    ESP_LOGE(TAG, "Failed to allocate decoded firmware buffer.");
                    cJSON_Delete(root);
                    free(response_buffer);
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }

                // Second call to mbedtls_base64_decode to actually decode the data.
                if (mbedtls_base64_decode(decoded_firmware, decoded_len, &decoded_len, (const unsigned char *)firmware_b64, b64_len) != 0) {
                    ESP_LOGE(TAG, "Base64 decoding failed!");
                    free(decoded_firmware);
                } else {
                    ESP_LOGI(TAG, "Base64 decoded successfully. Binary size: %d bytes", decoded_len);

                    esp_ota_handle_t update_handle = 0;
                    // Get the next OTA partition to write the new firmware to.
                    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);

                    if (update_partition == NULL) {
                        ESP_LOGE(TAG, "No valid OTA update partition found. Check partition table.");
                    } else {
                        ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
                                 update_partition->subtype, update_partition->address);

                        // Begin the OTA update process.
                        err = esp_ota_begin(update_partition, decoded_len, &update_handle);
                        if (err != ESP_OK) {
                            ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
                        } else {
                            // Write the decoded firmware data to the OTA partition.
                            err = esp_ota_write(update_handle, (const void *)decoded_firmware, decoded_len);
                            if (err != ESP_OK) {
                                ESP_LOGE(TAG, "esp_ota_write failed (%s)", esp_err_to_name(err));
                            } else {
                                // End the OTA update process.
                                err = esp_ota_end(update_handle);
                                if (err != ESP_OK) {
                                    ESP_LOGE(TAG, "esp_ota_end failed (%s)", esp_err_to_name(err));
                                } else {
                                    // Set the new partition as the boot partition.
                                    err = esp_ota_set_boot_partition(update_partition);
                                    if (err != ESP_OK) {
                                        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)", esp_err_to_name(err));
                                    } else {
                                        ESP_LOGI(TAG, "Update successful! Rebooting...");
                                        esp_restart(); // Reboot to load the new firmware
                                    }
                                }
                            }
                        }
                    }
                }
                free(decoded_firmware); // Free the decoded firmware buffer
                cJSON_Delete(root); // Free cJSON allocated memory
                free(response_buffer); // Free the HTTP response buffer

            } else if (status_code == 404) {
                ESP_LOGI(TAG, "Server has no firmware available yet (404 Not Found). Waiting...");
            } else {
                ESP_LOGE(TAG, "Server returned an error: %d", status_code);
            }
        } else {
            ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        }

        esp_http_client_cleanup(client); // Clean up HTTP client resources
        ESP_LOGI(TAG, "Next check in %d seconds.", OTA_CHECK_INTERVAL_MS / 1000);
        vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS); // Wait before checking again
    }
}

// --- Post Device Version ---
// This function sends the current device version to the Flask server.
void post_device_version(const char* version) {
    char url[128];
    // Construct the URL for posting device version.
    snprintf(url, sizeof(url), "http://%s:%s/device_version", SERVER_IP, SERVER_PORT);

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST, // Use POST method
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client for version post.");
        return;
    }

    char post_data[128];
    // Create JSON payload for the version.
    snprintf(post_data, sizeof(post_data), "{\"version\":\"%s\"}", version);

    // Set HTTP headers and post field.
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_err_t err = esp_http_client_perform(client); // Perform the POST request
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Posted device version: %s", version);
    } else {
        ESP_LOGE(TAG, "Failed to post device version: %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client); // Clean up HTTP client
}

// --- Main Application Entry Point ---
// This is the first function called when the ESP32 boots.
void app_main(void) {
    // Initialize NVS (Non-Volatile Storage) for Wi-Fi/Ethernet and other configurations.
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase()); // Erase NVS if it's full or version mismatch
      ret = nvs_flash_init(); // Re-initialize NVS
    }
    ESP_ERROR_CHECK(ret); // Check for any remaining NVS initialization errors

    ESP_LOGI(TAG, "Initializing Ethernet...");
    eth_init(); // Initialize and connect to Ethernet

    // Post the current device version to the server.
    // You should update "1.0.0" to your actual firmware version.
    post_device_version("1.0.0");

    // Create and start the OTA update task.
    // Stack size 8192 bytes (8KB) is generally sufficient for HTTP/JSON/OTA operations.
    xTaskCreate(&ota_update_task, "ota_update_task", 8192, NULL, 5, NULL);
}
