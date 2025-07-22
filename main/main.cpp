/*
 * ESP-IDF OTA Firmware Update Client
 *
 * This application connects to a Wi-Fi network and fetches a firmware update
 * from a custom HTTP server (the provided Python Flask app).
 *
 * It is designed for the Espressif IoT Development Framework (ESP-IDF).
 *
 * HOW IT WORKS:
 * 1. Initializes NVS (Non-Volatile Storage), which is required for Wi-Fi.
 * 2. Connects to the specified Wi-Fi network.
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
 * - Ensure HTTP Client and OTA libraries are enabled (they are by default).
 *
 * HOW TO USE:
 * 1. Create a new ESP-IDF project.
 * 2. Replace the contents of `main/main.c` with this code.
 * 3. Update the `WIFI_SSID`, `WIFI_PASS`, and `SERVER_IP` definitions below.
 * 4. Build and flash the project to your ESP32: `idf.py build flash monitor`
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "cJSON.h"
#include "mbedtls/base64.h"

// --- Configuration ---
// IMPORTANT: Replace with your network credentials
#define WIFI_SSID      "YOUR_WIFI_SSID"
#define WIFI_PASS      "YOUR_WIFI_PASSWORD"
// IMPORTANT: Replace with your PC's IP address (from ipconfig)
#define SERVER_IP      "YOUR_PC_IP_ADDRESS"
#define SERVER_PORT    "5000"
#define FIRMWARE_URL   "http://" SERVER_IP ":" SERVER_PORT "/firmware"

#define OTA_CHECK_INTERVAL_MS (30 * 1000) // Check every 30 seconds

// --- Globals ---
static const char *TAG = "OTA_CLIENT";
#define OTA_HTTP_BUFFER_SIZE 1024

// Event group to signal when we are connected
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static int s_retry_num = 0;

// --- Function Prototypes ---
void ota_update_task(void *pvParameter);

// --- Wi-Fi Event Handler ---
static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < 5) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retrying to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"Connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP address:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

// --- Wi-Fi Initialization ---
void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));


    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    // Wait until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
    // number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above)
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to AP SSID:%s", WIFI_SSID);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGW(TAG, "Failed to connect to SSID:%s", WIFI_SSID);
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }
}

// --- HTTP Event Handler for OTA ---
esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    // This basic handler is sufficient for our needs.
    // More complex logic can be added here if needed.
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
void ota_update_task(void *pvParameter) {
    ESP_LOGI(TAG, "Starting OTA update task...");

    esp_http_client_config_t config = {
        .url = FIRMWARE_URL,
        .event_handler = _http_event_handler,
        .keep_alive_enable = true,
    };

    while (1) {
        ESP_LOGI(TAG, "Checking for update from %s", FIRMWARE_URL);

        esp_http_client_handle_t client = esp_http_client_init(&config);
        esp_err_t err = esp_http_client_perform(client);

        if (err == ESP_OK) {
            int status_code = esp_http_client_get_status_code(client);
            ESP_LOGI(TAG, "HTTP GET Status = %d", status_code);

            if (status_code == 200) {
                // --- Process the response ---
                char *response_buffer = malloc(OTA_HTTP_BUFFER_SIZE + 1);
                int total_read_len = 0;
                int read_len = 0;
                if ((read_len = esp_http_client_read(client, response_buffer, OTA_HTTP_BUFFER_SIZE)) > 0) {
                    total_read_len += read_len;
                }
                response_buffer[total_read_len] = '\0'; // Null-terminate the string

                // --- Parse JSON ---
                cJSON *root = cJSON_Parse(response_buffer);
                if (root == NULL) {
                    ESP_LOGE(TAG, "Failed to parse JSON response");
                    free(response_buffer);
                    esp_http_client_cleanup(client);
                    vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
                    continue;
                }

                cJSON *firmware_b64_json = cJSON_GetObjectItem(root, "bin_content_base64");
                if (!cJSON_IsString(firmware_b64_json) || (firmware_b64_json->valuestring == NULL)) {
                    ESP_LOGE(TAG, "JSON does not contain 'bin_content_base64' string.");
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
                // mbedTLS needs a buffer for the decoded data. The decoded size will be at most 3/4 of the b64 size.
                unsigned char *decoded_firmware = malloc(b64_len); 

                if (mbedtls_base64_decode(decoded_firmware, b64_len, &decoded_len, (const unsigned char *)firmware_b64, b64_len) != 0) {
                    ESP_LOGE(TAG, "Base64 decoding failed!");
                } else {
                    ESP_LOGI(TAG, "Base64 decoded successfully. Binary size: %d bytes", decoded_len);
                    
                    esp_ota_handle_t update_handle = 0;
                    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
                    
                    if (update_partition == NULL) {
                        ESP_LOGE(TAG, "No valid OTA update partition found.");
                    } else {
                         ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
                                 update_partition->subtype, update_partition->address);

                        err = esp_ota_begin(update_partition, decoded_len, &update_handle);
                        if (err != ESP_OK) {
                            ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
                        } else {
                            err = esp_ota_write(update_handle, (const void *)decoded_firmware, decoded_len);
                            if (err != ESP_OK) {
                                ESP_LOGE(TAG, "esp_ota_write failed (%s)", esp_err_to_name(err));
                            } else {
                                err = esp_ota_end(update_handle);
                                if (err != ESP_OK) {
                                    ESP_LOGE(TAG, "esp_ota_end failed (%s)", esp_err_to_name(err));
                                } else {
                                    err = esp_ota_set_boot_partition(update_partition);
                                    if (err != ESP_OK) {
                                        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)", esp_err_to_name(err));
                                    } else {
                                        ESP_LOGI(TAG, "Update successful! Rebooting...");
                                        esp_restart();
                                    }
                                }
                            }
                        }
                    }
                }
                free(decoded_firmware);
                cJSON_Delete(root);
                free(response_buffer);

            } else if (status_code == 404) {
                 ESP_LOGI(TAG, "Server has no firmware available yet. Waiting...");
            } else {
                ESP_LOGE(TAG, "Server returned an error: %d", status_code);
            }
        } else {
            ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        }

        esp_http_client_cleanup(client);
        ESP_LOGI(TAG, "Next check in %d seconds.", OTA_CHECK_INTERVAL_MS / 1000);
        vTaskDelay(OTA_CHECK_INTERVAL_MS / portTICK_PERIOD_MS);
    }
}


// --- Main Application Entry Point ---
void app_main(void) {
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();

    // Start the OTA update task
    xTaskCreate(&ota_update_task, "ota_update_task", 8192, NULL, 5, NULL);
}
