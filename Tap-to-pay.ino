#include <SPI.h>
#include <MFRC522.h>
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <WiFiClientSecureBearSSL.h>
//-----------------------------------------
#define RST_PIN D3
#define SS_PIN D4
//-----------------------------------------
MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;
MFRC522::StatusCode status;
//-----------------------------------------
/* Be aware of Sector Trailer Blocks */
int blockNum = 2;
/* Create another array to read data from Block */
/* Legthn of buffer should be 2 Bytes more than the size of Block (16 Bytes) */
byte bufferLen = 18;
byte readBlockData[18];
//-----------------------------------------
String card_holder_name;
const String sheet_url = "https://script.google.com/macros/s/AKfycbzTaSksr5Y9Ys-tjXTxyPmirXru_j9Buakr4p9bQmFJXzSul_dOjkUcHT1ZMfTgMn6mng/exec?name=";
//-----------------------------------------
// Fingerprint for demo URL
const uint8_t fingerprint[20] = { 0x8d, 0xc5, 0x65, 0x10, 0x71, 0x12, 0x6b, 0x24, 0x9b, 0x99, 0x8c, 0x1f, 0xa9, 0x0c, 0xd1, 0x0e, 0x07, 0xc0, 0x4d, 0xa4 };
//8D C5 65 10 71 12 6B 24 9B 99 8C 1F A9 0C D1 0E 07 C0 4D A4
//-----------------------------------------
#define WIFI_SSID "TAPTOPAY"
#define WIFI_PASSWORD "123456789"
//-----------------------------------------




/****************************************************************************************************
 * setup() function
 ****************************************************************************************************/
void setup() {
  //--------------------------------------------------
  /* Initialize serial communications with the PC */
  Serial.begin(9600);
  //Serial.setDebugOutput(true);
  //--------------------------------------------------
  //WiFi Connectivity
  Serial.println();
  Serial.println();
  Serial.print("Connecting to wifi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(200);
  }
  Serial.println("");
  Serial.println("WiFi connected.");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
  Serial.println();
  Serial.println("##################### WELCOME TO TAP-TO-PAY #####################");
  Serial.println();

  //--------------------------------------------------
  /* Initialize SPI bus */
  SPI.begin();
  mfrc522.PCD_Init();
  //--------------------------------------------------
}




/****************************************************************************************************
 * loop() function
 ****************************************************************************************************/
void loop() {
  //--------------------------------------------------
  /* Initialize MFRC522 Module */
  mfrc522.PCD_Init();
  /* Look for new cards */
  /* Reset the loop if no new card is present on RC522 Reader */
  if (!mfrc522.PICC_IsNewCardPresent()) { return; }

  // If card found find it's UID
  String tag;
  if (mfrc522.PICC_ReadCardSerial()) {
    for (byte i = 0; i < 4; i++) {
      tag += mfrc522.uid.uidByte[i];
    }
  }

  /* Read data from the same block */
  //--------------------------------------------------
  Serial.println();
  Serial.println(F("Reading balance from your ID Card..."));
  ReadDataFromBlock(blockNum, readBlockData);

  /* Print the data */
  String amt = String((char*)readBlockData);
  int amount = amt.toInt();
  Serial.println();
  Serial.print(F("Card Balance:"));
  Serial.println(amt);
  Serial.println();


  if (amount - 15 < 0) {
    Serial.println("----INSUFFICIENT AMOUNT----");
    Serial.println("**Please recharge your card**");
    delay(3000);
    return;
  }

  //MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
  if (WiFi.status() == WL_CONNECTED) {
    //-------------------------------------------------------------------------------
    std::unique_ptr<BearSSL::WiFiClientSecure> client(new BearSSL::WiFiClientSecure);
    //-------------------------------------------------------------------------------
    // client->setFingerprint(fingerprint);
    client->setInsecure();
    amount = amount - 15;
    amt = String(amount);
    byte blockData[16];
    amt.getBytes(blockData, 16);
    WriteDataToBlock(blockNum, blockData);

    card_holder_name = sheet_url + tag + "_" + String(amount);
    card_holder_name.trim();
    Serial.println(card_holder_name);
    //-----------------------------------------------------------------
    HTTPClient https;
    Serial.print(F("[HTTPS] begin...\n"));
    //-----------------------------------------------------------------

    //NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
    if (https.begin(*client, (String)card_holder_name)) {
      //-----------------------------------------------------------------
      // HTTP
      Serial.print(F("[HTTPS] GET...\n"));
      // start connection and send HTTP header
      int httpCode = https.GET();
      //-----------------------------------------------------------------
      // httpCode will be negative on error
      if (httpCode > 0) {
        // HTTP header has been send and Server response header has been handled
        Serial.printf("[HTTPS] GET... code: %d\n", httpCode);
        // file found at server
      }
      //-----------------------------------------------------------------
      else { Serial.printf("[HTTPS] GET... failed, error: %s\n", https.errorToString(httpCode).c_str()); }
      //-----------------------------------------------------------------
      https.end();

      Serial.println();
      Serial.print(F("Card Balance:"));
      Serial.println(amt);
      Serial.println();

      delay(1000);
    }
    //NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
    else {
      Serial.printf("[HTTPS} Unable to connect\n");
    }
    //NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
  }
  //MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
}




/****************************************************************************************************
 * ReadDataFromBlock() function
 ****************************************************************************************************/
void ReadDataFromBlock(int blockNum, byte readBlockData[]) {
  //----------------------------------------------------------------------------
  /* Prepare the ksy for authentication */
  /* All keys are set to FFFFFFFFFFFFh at chip delivery from the factory */
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }
  //----------------------------------------------------------------------------
  /* Authenticating the desired data block for Read access using Key A */
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));
  //----------------------------------------------------------------------------s
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Authentication failed for Read: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  //----------------------------------------------------------------------------
  else {
    Serial.println("Authentication success");
  }
  //----------------------------------------------------------------------------
  /* Reading data from the Block */
  status = mfrc522.MIFARE_Read(blockNum, readBlockData, &bufferLen);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Reading failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  //----------------------------------------------------------------------------
  else {
    Serial.println("Card was read successfully");
  }
  //----------------------------------------------------------------------------
}

void WriteDataToBlock(int blockNum, byte blockData[]) {
  //----------------------------------------------------------------------------
  /* Prepare the ksy for authentication */
  /* All keys are set to FFFFFFFFFFFFh at chip delivery from the factory */
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }
  //------------------------------------------------------------------------------
  /* Authenticating the desired data block for write access using Key A */
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Authentication failed for Write: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  //------------------------------------------------------------------------------
  else {
    Serial.println("Authentication success");
  }
  //------------------------------------------------------------------------------
  /* Write data to the block */
  status = mfrc522.MIFARE_Write(blockNum, blockData, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Writing to Block failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else {
    Serial.println("Amount was updated...");
  }
  //------------------------------------------------------------------------------
}