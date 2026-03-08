#include <iostream>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <cpprest/uri_builder.h>
#include <cpprest/http_msg.h>
#include <cpprest/http_listener.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>
#include <xlnt/xlnt.hpp>
#include <fstream>
using namespace std;
using namespace web;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;
#include <string>
using namespace utility;
using namespace web;
using namespace web::http;
using namespace web::http::client;

//Previously Hard Coded removed for GitHub Upload
std::string access_key;
std::string secret_key;
std::string session_token;
std::string amazon_access_token;
std::string client_id;
std::string client_secret;
std::string refresh_token;

// Implements rest api back end for requesting a new Amazon access token
#include <mutex>

std::mutex access_token_mutex;  // Mutex to protect access to amazon_access_token

void request_new_access_token() {
    try {
        http_client client(U("https://api.amazon.com/auth/o2/token"));
        uri_builder builder(U(""));

        std::string request_body = "grant_type=refresh_token&refresh_token=" + refresh_token + "&client_id=" + client_id + "&client_secret=" + client_secret;

        http_request request(methods::POST);
        request.headers().add(U("Content-Type"), U("application/x-www-form-urlencoded"));
        request.set_body(request_body);

        client.request(request).then([](const http_response& response) {
            if (response.status_code() == status_codes::OK) {
                return response.extract_json();
            } else {
                throw std::runtime_error("Failed to get new access token: " + std::to_string(response.status_code()));
            }
        }).then([](json::value json_response) {
            std::lock_guard<std::mutex> lock(access_token_mutex);  // Lock the mutex before accessing shared resource

            // Update the global amazon_access_token
            amazon_access_token = utility::conversions::to_utf8string(json_response[U("access_token")].as_string());

            std::wcout << L"New access token: " << json_response[U("access_token")].as_string() << std::endl;
        }).wait();
    } catch (const std::exception& e) {
        std::cerr << "Exception in request_new_access_token: " << e.what() << std::endl;
    }
}


// Function to continuously refresh Amazon access keys
void refresh_keys() {
    while (true) {
        request_new_access_token();  // Already protected by mutex inside this function

        std::lock_guard<std::mutex> lock(access_token_mutex);
        std::cout << "Access token refreshed: " << amazon_access_token << std::endl;

        std::this_thread::sleep_for(std::chrono::minutes(50));
    }
}



// Function to generate HMAC-SHA256 signature
std::string hmac_sha256(const std::string &key, const std::string &data) {
    unsigned char* result;  // Variable to hold HMAC result
    static char res_hexstring[65];  // Buffer to store the hex-encoded result
    // Perform HMAC-SHA256 with the given key and data
    result = HMAC(EVP_sha256(), reinterpret_cast<const unsigned char*>(key.c_str()), static_cast<int>(key.length()), reinterpret_cast<const unsigned char*>(data.c_str()), static_cast<int>(data.length()), nullptr, nullptr);
    // Convert the result to a hex-encoded string
    for (int i = 0; i < 32; i++) {
        sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
    }
    return std::string{res_hexstring};  // Return the hex-encoded string
}

// Function to compute SHA-256 hash of a

std::string sha256_hash(const std::string &str) {
    unsigned char hash[EVP_MAX_MD_SIZE];  // Buffer to hold the hash (use EVP_MAX_MD_SIZE for flexibility)
    unsigned int length_of_hash = 0;  // Variable to store the hash length

    EVP_MD_CTX* context = EVP_MD_CTX_new();  // Create a new EVP context
    if (context == nullptr) {
        throw std::runtime_error("Failed to create EVP context");
    }

    EVP_DigestInit_ex(context, EVP_sha256(), nullptr);  // Initialize SHA-256 context
    EVP_DigestUpdate(context, str.c_str(), str.length());  // Update context with input string
    EVP_DigestFinal_ex(context, hash, &length_of_hash);  // Finalize and get the hash
    EVP_MD_CTX_free(context);  // Clean up the context

    // Convert the hash bytes to a hex string
    std::stringstream ss;
    for (unsigned int i = 0; i < length_of_hash; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();  // Return the hex-encoded hash
}


// Function to generate an Amazon date in the format YYYYMMDD'T'HHMMSS'Z'
std::string get_amz_date() {
    auto now = std::chrono::system_clock::now();  // Get the current time
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);  // Convert to time_t format
    std::tm now_tm = {};  // Zero-initialize the tm structure
    gmtime_s(&now_tm, &now_c);  // Use gmtime_s to convert time_t to tm
    std::ostringstream amz_date;  // String stream to format the date
    amz_date << std::put_time(&now_tm, "%Y%m%dT%H%M%SZ");  // Format the date as Amazon expects
    return amz_date.str();  // Return the formatted date
}

// Function to generate a date stamp in the format YYYYMMDD
std::string get_date_stamp() {
    auto now = std::chrono::system_clock::now();  // Get the current time
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);  // Convert to time_t format
    std::tm now_tm = {};  // Zero-initialize the tm structure
    gmtime_s(&now_tm, &now_c);  // Use gmtime_s to convert time_t to tm
    std::ostringstream date_stamp;  // String stream to format the date
    date_stamp << std::put_time(&now_tm, "%Y%m%d");  // Format the date as YYYYMMDD
    return date_stamp.str();  // Return the formatted date stamp
}


// Generates AWS signature for API requests
std::string generate_aws_signature(const std::string &method, const std::string &canonical_uri, const std::string &query_string, const std::string &access, const std::string &secret, const std::string &region, const std::string &service, const std::string &payload_hash) {
    std::string host = "sellingpartnerapi-na.amazon.com";  // Amazon SP-API host
    std::string amz_date = get_amz_date();  // Get current date in Amazon format
    std::string date_stamp = get_date_stamp();  // Get current date in YYYYMMDD format
    std::string canonical_headers = "host:" + host + "\n" + "x-amz-date:" + amz_date + "\n";  // Canonical headers for AWS
    std::string signed_headers = "host;x-amz-date";  // Signed headers required for the request
    // Canonical request that includes method, headers, and hash of payload
    std::string canonical_request = method + "\n" + canonical_uri + "\n" + query_string + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash;
    std::string algorithm = "AWS4-HMAC-SHA256";  // Signature algorithm
    // Credential scope defines the date, region, and service for the request
    std::string credential_scope = date_stamp + "/" + region + "/" + service + "/aws4_request";
    // String to sign, which is the combination of algorithm, date, and request hash
    std::string string_to_sign = algorithm + "\n" + amz_date + "\n" + credential_scope + "\n" + sha256_hash(canonical_request);
    // Generate signing key by applying HMAC-SHA256 with the secret key and date/region/service
    std::string k_secret = "AWS4" + secret;
    std::string k_date = hmac_sha256(k_secret, date_stamp);
    std::string k_region = hmac_sha256(k_date, region);
    std::string k_service = hmac_sha256(k_region, service);
    std::string k_signing = hmac_sha256(k_service, "aws4_request");
    // Final signature is computed by applying HMAC-SHA256 to the string to sign
    std::string signature = hmac_sha256(k_signing, string_to_sign);
    // Create the final Authorization header to include in the request
    std::string authorization_header = algorithm + " " + "Credential=" + access + "/" + credential_scope + ", " + "SignedHeaders=" + signed_headers + ", " + "Signature=" + signature;
    return authorization_header;  // Return the computed authorization header
}

// Product class to represent a product with row, price, UPC, ASIN, etc.
class Product {
public:
    int row;
    double price;
    std::string upc;
    std::string asin;
    //int salesRank;
    std::string amazon;
    double listingPrice;

    // Constructor to initialize a Product object with row, price, and UPC
    Product(int r, double p, std::string u) : row(r), price(p), upc(std::move(u)), listingPrice(0.0) {}
};

// Rate-limiting logic for making API search requests
void rate_limited_request_search(const std::function<void()>& request_function) {
    static const double request_limit = 1.2;  // Limit the rate to 1.2 requests per second
    static const std::chrono::milliseconds rate_limit_interval(static_cast<int>(1000 / request_limit));  // Calculate the rate limit interval
    static auto last_request_time = std::chrono::steady_clock::now();  // Track the time of the last request

    auto now = std::chrono::steady_clock::now();  // Get the current time
    auto elapsed_time = now - last_request_time;  // Calculate the time elapsed since the last request

    // If the elapsed time is less than the rate limit, sleep until the next allowed request
    if (elapsed_time < rate_limit_interval) {
        std::this_thread::sleep_for(rate_limit_interval - elapsed_time);
    }

    try {
        // Log the timestamp of the request and call the provided request function
        std::cout << "Making rate-limited search request at: " << std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() << " ms\n";
        request_function();
    } catch (const std::exception& e) {
        // Handle any exceptions that occur during the request
        std::cerr << "Exception in rate_limited_request_search: " << e.what() << std::endl;
    }

    // Update the time of the last request
    last_request_time = std::chrono::steady_clock::now();
}

// Rate-limiting logic for making competitive summary requests
void rate_limited_request_competitive(const std::function<void()>& request_function) {
    static const std::chrono::seconds rate_limit_interval(2);  // Limit to 1 request every 2 seconds
    static auto last_request_time = std::chrono::steady_clock::now();  // Track the time of the last request

    auto now = std::chrono::steady_clock::now();  // Get the current time
    auto elapsed_time = now - last_request_time;  // Calculate the time elapsed since the last request

    // If the elapsed time is less than the rate limit, sleep until the next allowed request
    if (elapsed_time < rate_limit_interval) {
        std::this_thread::sleep_for(rate_limit_interval - elapsed_time);
    }

    try {
        // Log the timestamp of the request and call the provided request function
        std::cout << "Making rate-limited competitive request at: " << std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() << " ms\n";
        request_function();
    } catch (const std::exception& e) {
        // Handle any exceptions that occur during the request
        std::cerr << "Exception in rate_limited_request_competitive: " << e.what() << std::endl;
    }

    // Update the time of the last request
    last_request_time = std::chrono::steady_clock::now();
}

void searchCatalogItems(std::vector<Product>& productBatch) {
    int max_retries = 5; // Maximum number of retry attempts for throttling or failure cases
    int retry_count = 0; // Counter to track the number of retry attempts
    std::chrono::milliseconds backoff(1000); // Initial backoff time (1 second) before retrying

    // Start a retry loop to handle potential throttling or transient errors
    while (retry_count < max_retries) {
        try {
            // Set up AWS request details for calling the Amazon Selling Partner API
            std::string region = "us-east-1"; // AWS region
            std::string service = "execute-api"; // Service type (API gateway)
            std::string method = "GET"; // HTTP method (GET request)
            std::string canonical_uri = "/catalog/2022-04-01/items"; // URI for the catalog items
            std::string payload_hash = sha256_hash(""); // Generate a SHA-256 hash of an empty payload for signing

            // Generate the AWS authorization signature
            std::string authorization_header = generate_aws_signature(method, canonical_uri, "", access_key, secret_key, region, service, payload_hash);

            // Set up the HTTP client and request URL builder
            http_client client(U("https://sellingpartnerapi-na.amazon.com")); // API base URL
            uri_builder builder(U("/catalog/2022-04-01/items")); // API endpoint for the request

            // Create the query parameter string for UPC identifiers
            std::string identifiers;
            for (size_t i = 0; i < productBatch.size(); ++i) {
                if (i > 0) {
                    identifiers += ","; // Add a comma between UPCs
                }
                identifiers += productBatch[i].upc; // Append the UPC
            }
            // Append query parameters to the request URL
            builder.append_query(U("identifiers"), utility::conversions::to_string_t(identifiers));
            builder.append_query(U("includedData"), U("identifiers"));
            builder.append_query(U("identifiersType"), U("UPC"));
            builder.append_query(U("marketplaceIds"), U("ATVPDKIKX0DER"));
            builder.append_query(U("pageSize"), U("20"));

            // Set up the HTTP request object with headers
            http_request request(methods::GET);
            request.headers().add(U("Authorization"), utility::conversions::to_string_t(authorization_header)); // AWS authorization
            request.headers().add(U("x-amz-access-token"), utility::conversions::to_string_t(amazon_access_token)); // Amazon access token
            request.headers().add(U("Accept"), U("application/json")); // Set request to accept JSON response
            request.headers().add(U("Content-Type"), U("application/json")); // Specify JSON content type
            request.headers().add(U("region"), U("us-east-1")); // AWS region
            request.headers().add(U("X-Amz-Security-Token"), utility::conversions::to_string_t(session_token)); // AWS session token
            request.headers().add(U("X-Amz-Date"), utility::conversions::to_string_t(get_amz_date())); // Timestamp
            request.set_request_uri(builder.to_string()); // Attach the URI with parameters to the request

            // Perform a rate-limited request for the catalog search
            rate_limited_request_search([&client, &request, &productBatch]() {
                client.request(request)
                        .then([&productBatch](const http_response& response) {
                            // Log the status code from the response
                            std::wcout << U("Response Status Code: ") << response.status_code() << std::endl;

                            // Check if the response is successful (200 OK)
                            if (response.status_code() == status_codes::OK) {
                                return response.extract_json(); // Extract JSON from response
                            } else if (response.status_code() == 429) {
                                // Throttle error (too many requests), throw an exception to trigger retry
                                throw std::runtime_error("Throttling - HTTP status code: " + std::to_string(response.status_code()));
                            } else if (response.status_code() == 403) {
                                // Forbidden error (access denied), throw an exception
                                throw std::runtime_error("Forbidden - HTTP status code: " + std::to_string(response.status_code()));
                            }
                            // Other errors, throw a generic runtime exception
                            throw std::runtime_error("HTTP request failed with status code: " + std::to_string(response.status_code()));
                        })
                        .then([&productBatch](const pplx::task<json::value>& previousTask) {
                            try {
                                // Get and parse the JSON response
                                json::value const &v = previousTask.get();
                                std::wcout << U("Response Body: ") << v.serialize() << std::endl;

                                // Process the response if it contains "items"
                                if (v.has_field(U("items")) && v.at(U("items")).is_array()) {
                                    auto results = v.at(U("items")).as_array();
                                    // Iterate through the items and extract relevant information
                                    for (const auto& item : results) {
                                        if (item.has_field(U("asin"))) {
                                            std::string asin = utility::conversions::to_utf8string(item.at(U("asin")).as_string());
                                            int salesRank = -1;
                                            // Extract sales rank if available
                                            if (item.has_field(U("salesRanks")) && item.at(U("salesRanks")).is_array()) {
                                                auto salesRanks = item.at(U("salesRanks")).as_array();
                                                for (const auto& salesRankEntry : salesRanks) {
                                                    if (salesRankEntry.has_field(U("classificationRanks")) && salesRankEntry.at(U("classificationRanks")).is_array()) {
                                                        auto classificationRanks = salesRankEntry.at(U("classificationRanks")).as_array();
                                                        if (classificationRanks.size() > 0) {
                                                            salesRank = classificationRanks[0].at(U("rank")).as_integer();
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            // Process the UPC and match it with the product batch
                                            if (item.has_field(U("identifiers")) && item.at(U("identifiers")).is_array()) {
                                                auto identifiers = item.at(U("identifiers")).as_array();
                                                for (const auto& identifier : identifiers) {
                                                    if (identifier.has_field(U("identifiers")) && identifier.at(U("identifiers")).is_array()) {
                                                        auto idValues = identifier.at(U("identifiers")).as_array();
                                                        for (const auto& idValue : idValues) {
                                                            if (idValue.has_field(U("identifierType")) && idValue.at(U("identifierType")).as_string() == U("UPC") &&
                                                                idValue.has_field(U("identifier"))) {
                                                                std::string upc = utility::conversions::to_utf8string(idValue.at(U("identifier")).as_string());

                                                                // Match the UPC with a product in the batch
                                                                auto it = std::find_if(productBatch.begin(), productBatch.end(), [&](const Product& product) {
                                                                    return product.upc == upc && product.asin.empty();
                                                                });

                                                                // Update the product's ASIN if found
                                                                if (it != productBatch.end()) {
                                                                    it->asin = asin;
                                                                    std::wcout << U("Matched UPC: ") << utility::conversions::to_string_t(upc) << U(" with ASIN: ") << utility::conversions::to_string_t(asin) << std::endl;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch (http_exception const &e) {
                                // Handle HTTP-specific exceptions
                                std::cerr << "HTTP exception in searchCatalogItems: " << e.what() << std::endl;
                            } catch (std::exception const &e) {
                                // Handle general exceptions
                                std::cerr << "Exception in searchCatalogItems: " << e.what() << std::endl;
                            }
                        }).wait(); // Wait for the asynchronous request to complete
            });

            // Break the retry loop if the request was successful
            break;
        } catch (const std::runtime_error& e) {
            // Log the error message
            std::cerr << "Error: " << e.what() << std::endl;
            // Check if maximum retries have been reached
            if (++retry_count < max_retries) {
                // Log the retry attempt and wait before retrying
                std::cerr << "Retrying in " << backoff.count() << " milliseconds..." << std::endl;
                std::this_thread::sleep_for(backoff); // Wait before retrying
                backoff *= 2; // Apply exponential backoff for each retry
            } else {
                // Abort if the maximum number of retries has been reached
                std::cerr << "Max retries reached. Aborting." << std::endl;
                throw; // Rethrow the exception after maximum retries
            }
        }
    }
}

void getCompetitiveSummary(std::vector<Product>& productBatch) {
    std::this_thread::sleep_for(std::chrono::seconds(6));  // Throttle API calls by introducing a delay
    std::string region = "us-east-1";  // AWS region
    std::string service = "execute-api";  // AWS service for API calls
    std::string method = "POST";  // HTTP method (POST request)
    std::string canonical_uri = "/batches/products/pricing/2022-05-01/items/competitiveSummary";  // API endpoint URI
    std::string query_string;

    // Build the body of the POST request
    json::value body = json::value::object();  // JSON body object
    json::value requests = json::value::array();  // Array for request objects
    size_t index = 0;

    // Loop through the products and build individual requests for each ASIN
    for (const auto& product : productBatch) {
        if (!product.asin.empty()) {
            json::value request = json::value::object();  // JSON object for each product request
            request[U("asin")] = json::value::string(utility::conversions::to_string_t(product.asin));  // Add ASIN
            request[U("marketplaceId")] = json::value::string(U("ATVPDKIKX0DER"));  // Add marketplace ID
            request[U("includedData")] = json::value::array();  // Add included data
            request[U("includedData")][0] = json::value::string(U("featuredBuyingOptions"));  // Feature buying options
            request[U("method")] = json::value::string(U("GET"));  // HTTP method for this request
            request[U("uri")] = json::value::string(U("/products/pricing/2022-05-01/items/competitiveSummary"));  // URI
            requests[index++] = request;  // Append request to the array
        }
    }
    body[U("requests")] = requests;  // Set the array of requests as the body of the POST request

    // Generate the AWS signature for the request
    std::string payload_hash = sha256_hash(utility::conversions::to_utf8string(body.serialize()));  // Hash the payload
    std::string authorization_header = generate_aws_signature(method, canonical_uri, query_string, access_key, secret_key, region, service, payload_hash);  // Create the AWS signature

    // Set up the HTTP client and request details
    http_client client(U("https://sellingpartnerapi-na.amazon.com"));  // API base URL
    uri_builder builder(U("/batches/products/pricing/2022-05-01/items/competitiveSummary"));  // API endpoint URI
    http_request request(methods::POST);  // Create POST request

    // Add necessary headers to the request
    request.headers().add(U("Authorization"), utility::conversions::to_string_t(authorization_header));  // AWS Authorization
    request.headers().add(U("x-amz-access-token"), utility::conversions::to_string_t(amazon_access_token));  // Access token
    request.headers().add(U("Accept"), U("application/json"));  // Accept JSON response
    request.headers().add(U("Content-Type"), U("application/json"));  // Content type as JSON
    request.headers().add(U("region"), U("us-east-1"));  // AWS region
    request.headers().add(U("X-Amz-Security-Token"), utility::conversions::to_string_t(session_token));  // Session token
    request.headers().add(U("X-Amz-Date"), utility::conversions::to_string_t(get_amz_date()));  // Current date
    request.set_request_uri(builder.to_string());  // Set URI for the request
    request.set_body(body);  // Set the JSON body

    int max_retries = 5;  // Max number of retries in case of failure
    int retry_count = 0;  // Keep track of retry attempts
    std::chrono::milliseconds backoff(1000);  // Initial backoff time for retries

    // Retry loop in case of failure or throttling
    while (retry_count < max_retries) {
        try {
            // Perform a rate-limited request to get competitive summary
            rate_limited_request_competitive([&client, &request, &productBatch]() {
                client.request(request)
                        .then([&productBatch](const http_response& response) {
                            // Check if the response is OK (200)
                            if (response.status_code() == status_codes::OK) {
                                return response.extract_json();  // Extract JSON from the response
                            } else if (response.status_code() == 429) {
                                // Handle throttling error (429 Too Many Requests)
                                throw std::runtime_error("Throttling - HTTP status code: " + std::to_string(response.status_code()));
                            }
                            // For other errors, throw a runtime exception
                            throw std::runtime_error("HTTP request failed with status code: " + std::to_string(response.status_code()));
                        })
                        .then([&productBatch](const pplx::task<json::value>& previousTask) {
                            try {
                                json::value const &v = previousTask.get();  // Parse the JSON response
                                std::wcout << U("Response Body: ") << v.serialize() << std::endl;

                                // Check if the response contains the expected "responses" field
                                if (v.has_field(U("responses")) && v.at(U("responses")).is_array()) {
                                    auto results = v.at(U("responses")).as_array();
                                    // Loop through the results and update the products with their competitive summary
                                    for (const auto& item : results) {
                                        if (item.has_field(U("body")) && item.at(U("body")).has_field(U("asin"))) {
                                            std::string asin = utility::conversions::to_utf8string(item.at(U("body")).at(U("asin")).as_string());
                                            for (auto& product : productBatch) {
                                                if (product.asin == asin) {
                                                    // Check if the product has featured buying options and update the listing price
                                                    if (item.at(U("body")).has_field(U("featuredBuyingOptions")) &&
                                                        item.at(U("body")).at(U("featuredBuyingOptions")).is_array() &&
                                                        item.at(U("body")).at(U("featuredBuyingOptions")).size() > 0) {

                                                        for (const auto& buyingOption : item.at(U("body")).at(U("featuredBuyingOptions")).as_array()) {
                                                            if (buyingOption.has_field(U("segmentedFeaturedOffers")) &&
                                                                buyingOption.at(U("segmentedFeaturedOffers")).is_array() &&
                                                                buyingOption.at(U("segmentedFeaturedOffers")).size() > 0 &&
                                                                buyingOption.at(U("segmentedFeaturedOffers")).at(0).has_field(U("listingPrice")) &&
                                                                buyingOption.at(U("segmentedFeaturedOffers")).at(0).at(U("listingPrice")).has_field(U("amount"))) {

                                                                // Update the product's listing price with the price found
                                                                auto listingPrice = buyingOption.at(U("segmentedFeaturedOffers"))
                                                                        .at(0)
                                                                        .at(U("listingPrice"))
                                                                        .at(U("amount"))
                                                                        .as_double();
                                                                product.listingPrice = listingPrice;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch (http_exception const &e) {
                                // Handle HTTP-specific exceptions
                                std::cerr << "HTTP exception in getCompetitiveSummary: " << e.what() << std::endl;
                            } catch (std::exception const &e) {
                                // Handle general exceptions
                                std::cerr << "Exception in getCompetitiveSummary: " << e.what() << std::endl;
                            }
                        }).wait();  // Wait for the asynchronous request to complete
            });
            break;  // If successful, exit the retry loop
        } catch (const std::runtime_error& e) {
            // Log the error
            std::cerr << "Error: " << e.what() << std::endl;
            if (++retry_count < max_retries) {
                // Retry with exponential backoff if the max retries are not reached
                std::cerr << "Retrying in " << backoff.count() << " milliseconds..." << std::endl;
                std::this_thread::sleep_for(backoff);  // Wait before retrying
                backoff *= 2;  // Apply exponential backoff
            } else {
                // If max retries reached, abort
                std::cerr << "Max retries reached. Aborting." << std::endl;
                throw;  // Rethrow the exception
            }
        }
    }
}


std::vector<std::string> findProfitableProducts(const std::vector<Product>& products) {
    std::vector<std::string> profitableUPCs;  // Vector to store profitable UPCs
    std::ofstream outfile("profitable_upcs.txt");  // Open a file to write the profitable UPCs

    // Loop through each product to check profitability
    for (const auto& product : products) {
        // Skip products with listing price less than 17
        if (product.listingPrice < 25) {
            continue;
        }

        // Skip products not allowed on Amazon or needing approval
        if (product.amazon == "Not Allowed by Manufacturer" || product.amazon == "Approval Letter from Manufacturer Required") {
            continue;
        }

        // Check if the product is profitable (if the selling price is more than double the cost)
        if (product.price * 1.5 < product.listingPrice) {
            profitableUPCs.push_back(product.upc);  // Add profitable UPC to the vector
            outfile << product.upc << std::endl;  // Write profitable UPC to the file
        }
    }
    outfile.close();  // Close the file
    return profitableUPCs;  // Return the list of profitable UPCs
}
/*
void outputProductInfo(const std::vector<Product>& products) {
    std::ofstream outfile("product_info.txt");  // Open a file to write product info
    if (!outfile.is_open()) {
        std::cerr << "Failed to open the file for writing product info." << std::endl;
        return;
    }

    // Loop through each product and write its information to the file
    for (const auto& product : products) {
        outfile << "Product Information for UPC: " << product.upc << "\n";  // Write UPC
        outfile << "Row: " << product.row << "\n";  // Write row number
        outfile << "Price: $" << product.price << "\n";  // Write price
        outfile << "ASIN: " << product.asin << "\n";  // Write ASIN
        outfile << "Listing Price: $" << product.listingPrice << "\n";  // Write listing price
        outfile << "Amazon Decision: " << product.amazon << "\n";  // Write Amazon status
        outfile << "-------------------------\n";  // Divider for better readability
    }
    outfile.close();  // Close the file after writing
}
 */

std::vector<Product> process_excel_file(const std::string& file_path) {
    xlnt::workbook wb;  // Workbook object to handle the Excel file
    std::vector<Product> products;  // Vector to store products

    // Try to load the Excel file
    try {
        wb.load(file_path);
    } catch (const std::exception& e) {
        std::cerr << "Failed to load Excel file: " << e.what() << std::endl;
        throw;
    }

    std::cout << "Workbook loaded successfully.\n";  // Print success message

    xlnt::worksheet ws = wb.active_sheet();  // Get the active worksheet
    int price_column = -1;  // Variable to store price column index
    int upc_column = -1;  // Variable to store UPC column index

    // Search for columns that contain "Price" and "UPC"
    for (const auto& row : ws.rows(false)) {
        for (auto cell : row) {
            std::string cell_value = cell.to_string();

            // Search for the word "Price" in the cell, ignoring other addons
            if (cell_value.find("Price") != std::string::npos) {
                price_column = static_cast<int>(cell.column_index());
            }

            // Search for the word "UPC" in the cell, ignoring other addons
            if (cell_value.find("UPC") != std::string::npos) {
                upc_column = static_cast<int>(cell.column_index());
            }

            // If both columns are found, stop searching
            if (price_column != -1 && upc_column != -1) {
                break;
            }
        }

        // Exit outer loop if both columns are found
        if (price_column != -1 && upc_column != -1) {
            break;
        }
    }

    // Check if the Price or UPC columns were not found
    if (price_column == -1 || upc_column == -1) {
        std::cerr << "No 'Price' or 'UPC' column found." << std::endl;
        throw std::runtime_error("Missing necessary columns.");
    }

    bool header_skipped = false;  // Flag to skip the header row
    for (auto row : ws.rows(false)) {
        if (!header_skipped) {
            header_skipped = true;
            continue;  // Skip the header row
        }

        xlnt::cell price_cell = row[price_column - 1];  // Get the price cell
        xlnt::cell upc_cell = row[upc_column - 1];  // Get the UPC cell

        // Skip if the price or UPC cell has no value
        if (!price_cell.has_value() || !upc_cell.has_value()) {
            continue;
        }

        // Skip rows where price is not a number
        if (price_cell.data_type() != xlnt::cell_type::number) {
            continue;
        }

        // Get the price and UPC and add the product to the list
        double price = price_cell.value<double>();
        std::string upc = upc_cell.to_string();
        products.emplace_back(price_cell.row(), price, upc);  // Add the product to the list
    }

    return products;
}

// REST API handler for uploading Excel files
void handle_file_upload(web::http::http_request request) {
    try {
        std::cout << "Handling file upload request..." << std::endl;

        // Ensure the Content-Type is multipart/form-data
        utility::string_t content_type = request.headers().content_type();
        std::wcout << "Received content type: " << content_type << std::endl;

        if (content_type.find(U("multipart/form-data")) == utility::string_t::npos) {
            std::wcerr << "Unsupported content type: " << content_type << std::endl;
            auto response = http_response(web::http::status_codes::UnsupportedMediaType);
            response.headers().add(U("Access-Control-Allow-Origin"), U("http://localhost:8080"));
            response.set_body("Unsupported content type.");
            request.reply(response);
            return;
        }

        // Extract the boundary from the Content-Type header
        std::string boundary_prefix = "boundary=";
        size_t boundary_pos = content_type.find(utility::conversions::to_string_t(boundary_prefix));
        if (boundary_pos == std::string::npos) {
            std::cerr << "Error parsing Content-Type header: boundary not found." << std::endl;
            auto response = http_response(web::http::status_codes::BadRequest);
            response.headers().add(U("Access-Control-Allow-Origin"), U("http://localhost:8080"));
            response.set_body("Boundary not found.");
            request.reply(response);
            return;
        }

        std::string boundary = "--" + utility::conversions::to_utf8string(
                content_type.substr(boundary_pos + boundary_prefix.length()));
        std::cout << "Boundary: " << boundary << std::endl;

        request.extract_vector().then([boundary, request](std::vector<uint8_t> body_data) {
            if (body_data.empty()) {
                std::cerr << "File upload failed: received empty body." << std::endl;
                auto response = http_response(web::http::status_codes::BadRequest);
                response.headers().add(U("Access-Control-Allow-Origin"), U("http://localhost:8080"));
                response.set_body("File is empty.");
                request.reply(response);
                return;
            }

            // Convert the raw bytes into a string to parse the multipart body
            std::string body_str(body_data.begin(), body_data.end());

            // Find the file content part
            size_t file_start_pos = body_str.find(boundary);
            // How does this skip the headers//
            file_start_pos = body_str.find("\r\n\r\n", file_start_pos);  // Skip the headers
            if (file_start_pos == std::string::npos) {
                std::cerr << "Error parsing multipart data: no file content found." << std::endl;
                return;
            }

            // Extract the file content
            file_start_pos += 4;  // Skip over the \r\n\r\n
            size_t file_end_pos = body_str.find(boundary, file_start_pos) - 4;  // Exclude trailing \r\n\r\n
            std::string file_content = body_str.substr(file_start_pos, file_end_pos - file_start_pos);

            // Extract the filename (assume it's in the Content-Disposition header)
            size_t filename_pos = body_str.find("filename=\"");
            if (filename_pos == std::string::npos) {
                std::cerr << "Error parsing multipart data: filename not found." << std::endl;
                return;
            }
            filename_pos += 10;  // Skip past 'filename="'
            size_t filename_end_pos = body_str.find('\"', filename_pos);
            std::string filename = body_str.substr(filename_pos, filename_end_pos - filename_pos);

            // Save the file content
            std::ofstream fileStream(filename, std::ios::binary);
            if (!fileStream) {
                std::cerr << "Failed to open file for writing." << std::endl;
                return;
            }

            // Write the content to the file
            fileStream.write(file_content.c_str(), static_cast<std::streamsize>(file_content.size()));
            fileStream.close();

            std::cout << "File saved successfully as: " << filename << std::endl;

            // Determine the file type based on extension
            if (filename.find(".txt") != std::string::npos) {
                // Handle .txt file upload
                std::cout << "Processing .txt file: " << filename << std::endl;
            } else if (filename.find(".xlsx") != std::string::npos || filename.find(".xls") != std::string::npos) {
                // Handle Excel file upload
                std::thread key_refresh_thread(refresh_keys);
                key_refresh_thread.detach();
                request_new_access_token();

                // Use the process_excel_file function to process the Excel file
                std::vector<Product> products;
                try {
                    products = process_excel_file(filename); // Call process_excel_file
                } catch (const std::exception &e) {
                    std::cerr << "Error processing Excel file: " << e.what() << std::endl;
                    request.reply(web::http::status_codes::BadRequest, "Invalid Excel file format.");
                    return;
                }

                const size_t search_batch_size = 4;
                std::this_thread::sleep_for(std::chrono::seconds(3));
                for (size_t i = 0; i < products.size(); i += search_batch_size) {
                    std::vector<Product> searchBatch;
                    for (size_t j = i; j < i + search_batch_size && j < products.size(); ++j) {
                        searchBatch.push_back(products[j]);
                    }
                    if (!searchBatch.empty()) {
                        searchCatalogItems(searchBatch);
                    }

                    for (auto& product : searchBatch) {
                        auto it = std::find_if(products.begin(), products.end(), [&product](const Product& p) {
                            return p.row == product.row;
                        });
                        if (it != products.end()) {
                            *it = product;
                        }
                    }
                }

                const size_t competitive_summary_batch_size = 20;
                std::this_thread::sleep_for(std::chrono::seconds(10));
                for (size_t i = 0; i < products.size(); i += competitive_summary_batch_size) {
                    std::vector<Product> competitiveSummaryBatch;
                    for (size_t j = i; j < i + competitive_summary_batch_size && j < products.size(); ++j) {
                        if (!products[j].asin.empty()) {
                            competitiveSummaryBatch.push_back(products[j]);
                        }
                    }

                    if (competitiveSummaryBatch.empty()) {
                        continue; // Skip empty batches
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(33));
                    getCompetitiveSummary(competitiveSummaryBatch);

                    for (auto& product : competitiveSummaryBatch) {
                        auto it = std::find_if(products.begin(), products.end(), [&product](const Product& p) {
                            return p.row == product.row;
                        });
                        if (it != products.end()) {
                            *it = product;
                        }
                    }
                }

                auto profitableUPCs = findProfitableProducts(products);
                std::string upc_list = "Profitable UPCs:\n";
                for (const auto& upc : profitableUPCs) {
                    upc_list += upc + "\n";
                }
                std::string response_message = "File processed successfully.\n" + upc_list;
                auto response = http_response(web::http::status_codes::OK);
                response.headers().add(U("Access-Control-Allow-Origin"), U("http://localhost:8080"));
                response.set_body(response_message);
                request.reply(response);
            }
        }).wait();

    } catch (const std::exception &e) {
        std::cerr << "Error in file upload handling: " << e.what() << std::endl;
        auto response = http_response(web::http::status_codes::InternalError);
        response.headers().add(U("Access-Control-Allow-Origin"), U("http://localhost:8080"));
        response.set_body("File upload processing failed.");
        request.reply(response);
    }
}

int main() {
    http_listener listener (U("http://localhost:8081"));
    // Bind the OPTIONS method to handle CORS preflight requests
    listener.support(methods::OPTIONS, [](const http_request& request) {
        auto response = http_response(status_codes::OK);
        response.headers().add(U("Access-Control-Allow-Origin"), U("http://localhost:8080"));  // Allow your frontend
        response.headers().add(U("Access-Control-Allow-Methods"), U("POST, GET, OPTIONS"));
        response.headers().add(U("Access-Control-Allow-Headers"), U("Content-Type"));
        response.headers().add(U("Access-Control-Allow-Credentials"), U("true"));  // Optional: Allow credentials
        request.reply(response);
    });

    // Bind the POST method to the handle_file_upload function
    listener.support(methods::POST, [](const http_request& request) {
        try {
            // Just call handle_file_upload, which will handle the entire flow
            handle_file_upload(request);
        } catch (const std::exception& e) {
            std::cerr << "Error handling POST request: " << e.what() << std::endl;
            request.reply(status_codes::InternalError, "Error processing file upload");
        }
    });

    // Start the server
    try {
        listener
                .open()
                .then([&listener]() {
                    std::wcout << L"Listening on: " << listener.uri().to_string() << std::endl;
                })
                .wait();

        // Keep the server running
        std::string line;
        std::cout << "Press ENTER to exit." << std::endl;
        std::getline(std::cin, line);
    } catch (const std::exception& e) {
        std::cerr << "Error starting server: " << e.what() << std::endl;
    }
    return 0;
}




