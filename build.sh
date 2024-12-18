#!/bin/bash

# Variables
ASN_DIR="include"
SRC_DIR="src"
OUTPUT="final"


# Run asn1c
asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D "$ASN_DIR"/ asn/s1ap_v12.asn

# Remove Sample Files
rm -rf "$ASN_DIR"/*example* "$ASN_DIR"/Makefile*

# Compile generated ASN.1 files
gcc -I"$ASN_DIR" -c "$ASN_DIR"/*.c

# Compile main.c
gcc -I"$ASN_DIR" -c "$SRC_DIR"/*.c

# Link all object files
gcc -o $OUTPUT *.o -lsctp


# Clean up object files
rm *.o

# Run the program
echo -e "\n\n\n\t\t\tRunning the program:\n"

./$OUTPUT

echo -e "\n\n\t\t\tEnd Of The Program.\n\n\n"


# Clean up output and ASN files
rm $OUTPUT

rm -rf "$ASN_DIR"/*









