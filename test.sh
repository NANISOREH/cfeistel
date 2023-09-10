#!/bin/bash

# Initialize variables with default values
file_size=0  
unit_flag="B"  # Default to bytes
encryption_mode="cbc" 
debug_mode=false  

# Function to convert megabytes to bytes
convert_to_bytes() {
    local mb="$1"
    echo "$((mb * 1024 * 1024))"
}

# Function to convert bytes to megabytes
convert_to_mb() {
    local bytes="$1"
    echo "$((bytes / 1024 / 1024)) MB"
}

# Function to display script usage
display_usage() {
    echo "Usage: $0 [-mb] <file_size> [-m <mode>] [debug]"
}

# Check if the input file size and optional "debug" argument are provided as arguments
if [ "$#" -eq 0 ] || [ "$#" -gt 4 ]; then
    display_usage
    exit 1
fi

# Function to check if the make command produced errors or warnings
check_make_output() {
    local make_output_file="$1"
    local errors_warnings
    errors_warnings=$(grep -E '(error:|warning:)' "$make_output_file")
    if [ -n "$errors_warnings" ]; then
        echo "Compilation failed. Errors and warnings:"
        echo "$errors_warnings"
        rm "$make_output_file"
        exit 1
    else
        rm "$make_output_file"
    fi
}

# Process command line arguments
while [ "$#" -gt 0 ]; do
    case "$1" in
        -mb)
            unit_flag="MB"
            shift
            ;;
        -m)
            shift
            encryption_mode="$1"
            shift
            ;;
        debug)
            debug_mode=true  # Enable debug mode
            shift
            ;;
        *)
            # Check if the argument is numeric
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                file_size="$1"
            else
                echo "Error: Invalid argument: $1"
                display_usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if the unit is MB and convert to bytes if necessary
if [ "$unit_flag" == "MB" ]; then
    file_size=$(convert_to_bytes "$file_size")
fi

# Generate a random input file named "in" of the specified size
head -c "$file_size" /dev/urandom > "in"

# Display information about the chosen options
echo "Options chosen:"
if [ "$unit_flag" == "MB" ]; then
    echo "  File Size: $(convert_to_mb "$file_size")"
else
    echo "  File Size: $file_size bytes"
fi
echo "  Encryption Mode: $encryption_mode"
echo "  Debug Mode: $debug_mode"  # Display debug mode status

# Calculate and store the MD5 checksum of the original "in" file
original_md5sum=$(md5sum "in" | awk '{print $1}')

# Create a temporary file for make output
make_output_file=$(mktemp)

# Check if the "debug" argument is provided
if [ "$debug_mode" = true ]; then
    # Recompile and execute the program with debug flags (block logging is redirected to files)
    make CFLAGS="-DDEBUG -DQUIET -DSEQ" > "$make_output_file" 2>&1
    check_make_output "$make_output_file"
    { ./cfeistel enc -m "$encryption_mode" -i "in" -o "out"; } > "enc_debug.txt" 2>&1
    { ./cfeistel dec -m "$encryption_mode" -i "out" -o "in"; } > "dec_debug.txt" 2>&1
else
    make CFLAGS="-DQUIET" > "$make_output_file" 2>&1
    check_make_output "$make_output_file"
    ./cfeistel enc -m "$encryption_mode" -i "in" -o "out"
    ./cfeistel dec -m "$encryption_mode" -i "out" -o "in"
fi

# Calculate and store the MD5 checksum of the decrypted "in" file
decrypted_md5sum=$(md5sum "in" | awk '{print $1}')

# Check if the MD5 checksums match
if [ "$original_md5sum" == "$decrypted_md5sum" ]; then
    echo "Encryption and decryption successful. MD5 checksums match."
else
    echo "Error: MD5 checksums do not match. Encryption or decryption failed."
fi

# Clean up temporary files
rm "in" "out" "cfeistel"

exit 0
