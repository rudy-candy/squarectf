#include <stdio.h>
#include <string.h>
#include <stdlib.h>

unsigned char pan[10] = {0};
char customer[27] = {0};

const int tags[77] = {
        0x9F26, 0x9F42, 0x9F44, 0x9F05, 0x5F25, 0x5F24, 0x94, 0x4F, 0x82, 0x50, 0x9F12, 0x5A, 0x5F34, 0x87,
        0x9F3B, 0x9F43, 0x61, 0x9F36, 0x9F07, 0x9F08, 0x5F54, 0x8C, 0x8D, 0x5F20, 0x9F0B, 0x8E, 0x8F, 0x9F27,
        0x9F45, 0x84, 0x9D, 0x73, 0x9F49, 0xBF0C, 0xA5, 0x6F, 0x9F4C, 0x9F2D, 0x9F2E, 0x9F2F,
        0x9F46, 0x9F47, 0x9F48, 0x5F53, 0x9F0D, 0x9F0E, 0x9F0F, 0x9F10, 0x9F11, 0x5F28, 0x5F55, 0x5F56,
        0x42, 0x90, 0x9F32, 0x92, 0x5F50, 0x5F2D, 0x9F13, 0x9F4D, 0x9F4F, 0x9F14,
        0x9F17, 0x9F38, 0x70, 0x80, 0x77, 0x5F30, 0x88, 0x9F4B, 0x93, 0x9F4A,
        0x9F1F, 0x9F20, 0x57, 0x97, 0x9F23
};

const char *names[77] = {
        "Application Cryptogram", "Application Currency Code", "Application Currency Exponent",
        "Application Discretionary Data", "Application Effective Date", "Application Expiration Date",
        "Application File Locator (AFL)", "Application Identifier (AID) - card", "Application Interchange Profile",
        "Application Label", "Application Preferred Name", "Application Primary Account Number (PAN)",
        "Application Primary Account Number (PAN) Sequence Number", "Application Priority Indicator",
        "Application Reference Currency", "Application Reference Currency Exponent", "Application Template",
        "Application Transaction Counter (ATC)", "Application Usage Control", "Application Version Number",
        "Bank Identifier Code (BIC)", "Card Risk Management Data Object List 1 (CDOL1)",
        "Card Risk Management Data Object List 2 (CDOL2)", "Cardholder Name",
        "Cardholder Name Extended", "Cardholder Verification Method (CVM) List",
        "Certification Authority Public Key Index", "Cryptogram Information Data",
        "Data Authentication Code", "Dedicated File (DF) Name", "Directory Definition File (DDF) Name",
        "Directory Discretionary Template", "Dynamic Data Authentication Data Object List (DDOL)",
        "File Control Information (FCI) Issuer Discretionary Data",
        "File Control Information (FCI) Proprietary Template", "File Control Information (FCI) Template",
        "ICC Dynamic Number", "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate",
        "Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent",
        "Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder",
        "Integrated Circuit Card (ICC) Public Key Certificate", "Integrated Circuit Card (ICC) Public Key Exponent",
        "Integrated Circuit Card (ICC) Public Key Remainder",
        "International Bank Account Number (IBAN)", "Issuer Action Code - Default", "Issuer Action Code - Denial",
        "Issuer Action Code - Online", "Issuer Application Data",
        "Issuer Code Table Index", "Issuer Country Code", "Issuer Country Code (alpha2 format)",
        "Issuer Country Code (alpha3 format)", "Issuer Identification Number (IIN)",
        "Issuer Public Key Certificate", "Issuer Public Key Exponent", "Issuer Public Key Remainder",
        "Issuer URL", "Language Preference",
        "Last Online Application Transaction Counter (ATC) Register", "Log Entry", "Log Format",
        "Lower Consecutive Offline Limit", "Personal Identification Number (PIN) Try Counter",
        "Processing Options Data Object List (PDOL)", "READ RECORD Response Message Template",
        "Response Message Template Format 1", "Response Message Template Format 2", "Service Code",
        "Short File Identifier (SFI)", "Signed Dynamic Application Data", "Signed Static Application Data",
        "Static Data Authentication Tag List", "Track 1 Discretionary Data", "Track 2 Discretionary Data",
        "Track 2 Equivalent Data", "Transaction Certificate Data Object List (TDOL)", "Upper Consecutive Offline Limit"
};

size_t current = 0;
unsigned char* saved[10];
char customers[10][27];

void copy_data(unsigned char* dest, const unsigned char* src, size_t length, size_t remainder) {
    size_t to_copy = length;
    if (remainder < length) {
        to_copy = remainder;
    }
    for (size_t i = 0; i < to_copy; i++) {
        dest[i] = src[i];
    }
}

size_t get_tag(const unsigned char *emv, size_t* tlv_length) {
    unsigned char first = *emv;
    unsigned char last_five = first & 0x1f;
    size_t pos = 1;
    if (last_five == 0x1f) {
        while (1) {
            if (((emv[pos++] >> 7) & 1) == 0) {
                // last byte
                break;
            }
        }
    }
    unsigned char tag[pos+1];
    size_t tag_as_int = 0;
    for (size_t i = 0; i < pos; i++) {
        tag[i] = emv[i];
        tag_as_int = (tag_as_int<<8) + emv[i];
    }
    tag[pos] = 0;

    *tlv_length = *tlv_length + pos;

    return tag_as_int;
}

int find_tag(size_t tag) {
    for (size_t i = 0; i < 77; i++) {
        if (tags[i] == tag) {
            printf("%s: ", names[i]);
            return 1;
        }
    }

    return 0;
}

size_t get_length(const unsigned char *emv, size_t* tlv_length) {
    size_t pos = *tlv_length;
    if (((emv[pos] >> 7) & 1) == 0) {
        // length is the subsequent 7 bits
        size_t length = emv[pos] & 0x7f;

        *tlv_length = *tlv_length + 1;
        return length;
    } else {
        // subsequent 7 bits encodes the number of bytes in the length field
        size_t length_bytes = emv[pos++] & 0x7f;
        if (length_bytes > 2) {
            // we do not allow more than 3 length bytes including the initial byte according to emv spec
            printf("length bytes not allowed to be greater than 3\n");
            return 0;
        }

        size_t length = 0;
        for (size_t i = 0; i < length_bytes; i++) {
            length = (length<<8) + emv[pos++];
        }

        *tlv_length = *tlv_length + length_bytes + 1;
        return length;
    }
}

void read_pan(unsigned char *emv, size_t length, size_t remainder) {
    for (int i = 0; i < length; i++) {
        if (((emv[i] & 0xF) > 0x9) || (((emv[i] & 0xF0) >> 4) > 0x9)) {
            printf("only numeric values allowed\n");
            return;
        }
    }

    if (length < 4) {
        printf("PAN length must be at least 4 bytes\n");
        return;
    }
    if (length > 10) {
        printf("PAN length can only be up to 10 bytes\n");
        return;
    }
    copy_data(pan, emv, length, remainder);

    for (size_t i = 0; i < length-2; i++) {
        printf("XX");
    }
    for (size_t i = length-2; i < length; i ++) {
        printf("%02X", (unsigned int) pan[i]);
    }
    printf("\n");
}

void read_value(unsigned char *emv, size_t length, size_t remainder) {
    if (remainder > 0) {
        unsigned char value[length], *value_pos = value;
        copy_data(value, emv, length, remainder);

        while(*value_pos) {
            printf("%02X", (unsigned int) *value_pos++);
        }
    }
    printf("\n");
}

void read_iin(unsigned char*emv, size_t length, size_t remainder) {
    for (int i = 0; i < 2; i++) {
        if (((emv[i] & 0xF) > 0x9) || (((emv[i] & 0xF0) >> 4) > 0x9)) {
            printf("only numeric values allowed\n");
            return;
        }
    }

    unsigned char amount[2];
    copy_data(amount, emv, length, remainder);

    for (size_t i = 0; i < 2; i++) {
        printf("%02X", amount[i]);
    }
    printf("\n");
}

void read_name(const unsigned char *emv, size_t length, size_t remainder) {
    if (length < 2) {
        printf("Cardholder Name must be at least 2 bytes\n");
        return;
    }
    if (length > 26) {
        printf("Cardholder Name can only be up to 26 bytes\n");
        return;
    }

    for (size_t i = 0; i < length; i++) {
        if (emv[i] < 0x20 || emv[i] > 0x7E) {
            printf("Invalid characters in Cardholder Name\n");
            return;
        }
    }

    size_t to_copy = length;
    if (remainder < length) {
        to_copy = remainder;
    }
    for (size_t i = 0; i < to_copy; i++) {
        customer[i] = (char) emv[i];
    }

    customer[to_copy] = 0;

    printf("%s\n", customer);
}

size_t process_tlv(unsigned char *emv, size_t emv_length) {
    size_t tlv_length = 0;
    size_t *tlv_length_ptr = &tlv_length;

    size_t tag = get_tag(emv, tlv_length_ptr);
    int found = find_tag(tag);
    if (!found) {
        printf("unknown tag\n");
        return emv_length;
    }

    size_t length = get_length(emv, tlv_length_ptr);
    size_t remainder = emv_length - tlv_length;

    switch (tag) {
        case 0x5A:
            read_pan(&emv[tlv_length], length, remainder);
            break;
        case 0x42:
            read_iin(&emv[tlv_length], length, remainder);
            break;
        case 0x5F20:
            read_name(&emv[tlv_length], length, remainder);
            break;
        default:
            read_value(&emv[tlv_length], length, remainder);
    }

    tlv_length += length;
    return tlv_length;
}

void save_customer(unsigned char* emv, size_t emv_length) {
    for (size_t i = 0; i < 10; i++) {
        if (strcmp(customer, customers[i]) == 0) {
            copy_data(saved[i], emv, emv_length, emv_length);
            return;
        }
    }

    strcpy(customers[current], customer);
    free(saved[current]);
    saved[current] = malloc(emv_length);
    copy_data(saved[current++], emv, emv_length, emv_length);
    if (current >= 10) {
        current = 0;
    }
}


void process_emv(unsigned char* emv, size_t emv_length) {
    unsigned char* emv_tmp = emv;
    int curr = 0;
    while (curr < emv_length) {
        size_t tlv_length = process_tlv(emv_tmp, (emv_length - curr));
        emv_tmp += tlv_length;
        curr += (int) tlv_length;
    }

    if (strlen(customer) > 0) {
        save_customer(emv, emv_length);
        memset(customer, 0, sizeof customer);
    }
}

void delete_customer(char* name) {
    for (size_t i = 0; i < 10; i++) {
        if (strcmp(name, customers[i]) == 0) {
            free(saved[i]);
            saved[i] = 0;
            for (size_t j = 0; j < 26; j++) {
                customers[i][j] = 0;
            }
            break;
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("EMV Parser\n");
    while (1) {
        printf("What would you like to do?\n");
        printf("(1) Input EMV record\n");
        printf("(2) Delete record\n");
        printf("> ");
        char choice = (char) getchar();
        getchar();

        switch (choice) {
            case '1':
                printf("Input EMV record encoded in TLV format: ");
                char input[513] = {0}, *pos = input;
                fgets(input, 512, stdin);
                input[strcspn(input, "\n")] = 0;
                printf("\n");

                unsigned char emv[257] = {0};
                int input_len = 0;
                while (input_len < 256) {
                    if (*pos == 0) {
                        break;
                    }
                    sscanf(pos, "%2hhx", &emv[input_len++]);
                    pos+=2;
                }

                process_emv(emv, input_len);
                break;
            case '2':
                printf("Input name of customer to delete record for: ");
                char name[27] = {0};
                fgets(name, 26, stdin);
                name[strcspn(name, "\n")] = 0;
                delete_customer(name);
                break;
            default:
                printf("not an option\n");
        }
    }
}


