#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

int main(int argc, char *argv[]) {

  // Declaration
  FILE *f1; // Handshake File
  FILE *f2; // Dictionary File
  unsigned char passphrase[64]; // Passphrase Buffer
  unsigned char essid[33]; // AP Essid
  unsigned char test_essid[33]; // Match against Essid
  int test_essid_length;
  int essid_match = 0; // Essid matching counter
  unsigned char test_amac[12];
  int amac_match;
  unsigned char test_smac[12];
  int smac_match;
  unsigned char amac[12]; // AP MAC
  unsigned char smac[12]; // Station MAC
  unsigned char anonce[64]; // AP Nonce
  unsigned char snonce[64]; // Station Nonce
  unsigned char data[256]; // Packet 2 Data
  unsigned char data_length;
  unsigned char mic[32]; // Message integrity check
  unsigned char pmk[32]; // Pairwise master Key
  int i; // Generic Counter
  int j; // Generic Inner Counter
  int k = 0; // Counter Keys tested
  unsigned char ptk[80]; // Pairwise transient Key
  const unsigned char pke_seed[23] = {0x50, 0x61, 0x69, 0x72, 0x77, 0x69, 0x73, 0x65,
    0x20, 0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6e, 0x73, 0x69,
    0x6f, 0x6e, 0x00}; // Pairwise Key Expansion
  int buffer;
  unsigned char *parsed_file;
  int file_length = 0;
  int beacon = 0;
  int handshake1 = 0;
  int handshake2 = 0;

  strcpy(essid, argv[2]);

  // Open Files
  f1 = fopen(argv[5], "rb");
  f2 = fopen(argv[4], "r");

  // Abort if no dictionary file
  if (f2 == NULL) {
    printf("Could not open dictionary file\n");
    return 1;
  }

  // Abort if no handshake file
  if (f1 == NULL) {
    printf("Could not open handshake file\n");
    return 1;
  }

  while (buffer != EOF) {
    buffer = fgetc(f1);
    file_length++;
  }

  rewind(f1); // Reset fgetc head

  parsed_file = malloc(file_length * sizeof(unsigned char)); // Dynamic RAM allocation

  for (i = 0; i < file_length; i++) {
    parsed_file[i] = fgetc(f1);
  }

  for (i = 0; i < file_length; i++) {
    if (parsed_file[i] == 0x80 && parsed_file[i+1] == 0x00 && !beacon) {
      test_essid_length = parsed_file[i + 37];
      for (j = 0; j < test_essid_length; j++) {
        test_essid[j] = parsed_file[i + 38 + j];
      }
      essid_match = 0;
      for (j = 0; j < test_essid_length; j++) {
        if (test_essid[j] == essid[j]) {
          essid_match++;
        }
        else {
          break;
        }
      }
      if (essid_match == strlen(essid)) {
        for (j = 0; j < 6; j++) {
          amac[j] = parsed_file[i + 10 + j];
        }
        beacon = 1;
      }
    }
    if (parsed_file[i] == 0x88 && parsed_file[i+1] == 0x02 && beacon && !handshake1) {
      for (j = 0; j < 6; j++) {
        test_amac[j] = parsed_file[i + 10 + j];
      }
      amac_match = 0;
      for (j = 0; j < 6; j++) {
        if (test_amac[j] == amac[j]) {
          amac_match++;
        }
        else {
          break;
        }
      }
      if (amac_match == 6) {
        for (j = 0; j < 6; j++) {
          smac[j] = parsed_file[i + 4 + j];
        }
        for (j = 0; j < 32; j++) {
          anonce[j] = parsed_file[i + 51 + j];
        }
        handshake1 = 1;
      }
    }
    if (parsed_file[i] == 0x88 && parsed_file[i+1] == 0x01 && beacon && handshake1 && !handshake2) {
      for (j = 0; j < 6; j++) {
        amac[j] = parsed_file[i + 4 + j];
      }
      for (j = 0; j < 6; j++) {
        smac[j] = parsed_file[i + 10 + j];
      }
      amac_match = 0;
      smac_match = 0;
      for (j = 0; j < 6; j++) {
        if (test_amac[j] == amac[j]) {
          amac_match++;
        }
        else {
          break;
        }
      }
      for (j = 0; j < 6; j++) {
        if (test_smac[j] == smac[j]) {
          smac_match++;
        }
        else {
          break;
        }
      }
      if (amac_match == 6 && smac_match == 6) {
        for (j = 0; j < 32; j++) {
          snonce[j] = parsed_file[i + 51 + j];
        }
        for (j = 0; j < 16; j++) {
          mic[j] = parsed_file[i + 115 + j];
          parsed_file[i + 115 + j] = 0x00;
        }
        for (j = 0; j < 99; j++) {
          data[j] = parsed_file[i + 34 + j];
        }
        data_length = data[98];
        for (j = 0; j < data_length; j++) {
          data[j + 99] = parsed_file[i + 35 + 98 + j];
        }
        handshake2 = 1;
      }
      else {
        handshake1 = 0;
      }
    }
    if (beacon && handshake1 && handshake2) {
      break;
    }
  }

  // Main Loop
  while (1) {
    fgets(passphrase, 255, f2);
    passphrase[strlen(passphrase) - 1] = '\0';

    // Break if out of Passwords
    if (passphrase[0] == '\0') {
      printf("Passphrase not in dictionary!\n");
      break;
    }

    // OpenSSL PBKDF2 HMAC -> Passphrase + Essid -> Pairwise Master Key
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), essid, strlen(essid), 4096, 32, pmk);

    // OpenSSL HMAC
    //HMAC(EVP_sha1(), );

    // Print output every 10th run
    if (k % 10 == 0) {
    printf("Keys tested: %d\n", k);
    printf("Master Key: ");
    for (i = 0; i < 32; i++) {
      printf("%02x ", pmk[i]); // Hexadecimal with leading Zero
    }
    printf("\n");
  }
    k++; // Increase Keys tested
    passphrase[0] = '\0'; // Clear passphrase
  }

  // Cleanup
  fclose(f1); // Handshake file
  fclose(f2); // Dictionary file
  return 0;
}
