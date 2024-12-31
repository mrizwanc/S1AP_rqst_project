## S1AP Request Project

In this project I am trying to build S1AP messages between MME and eNB.

## Directory Structure
- `asn/`: Contains ASN.1 definitions.
- `include/`: Header files and all the generated code from asn1c.
- `src/`: Source files for the application.



# Description of build.sh
Processes happen in the scripting file-
- Compile the .asn file
- Remove sample files generated from asn1c compilation
- Compile all the generated files from .asn compilation
- Compile c files to run s1ap
- Link all the object files and build the output file
- Clean all the object files
- Run the output file
- Clean the output file

