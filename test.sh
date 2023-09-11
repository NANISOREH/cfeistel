#!/bin/bash

# Initialize variables with default values
file_size=0  
unit_flag="B"  # Default to bytes
encryption_mode="ctr" 
debug_mode=false  
create_text_file=false  # Default to generating random bytes

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

# Function to generate random text of a specified length
generate_random_text() {
    local length="$1"
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

# Function to display script usage
display_usage() {
    echo "Usage: $0 [-mb] <file_size> [-m <mode>] [-t] [debug]"
}

# Function to append the content of one file to another
append_to_file() {
    local dest_file="$1"
    local src_file="$2"
    local content="$3"

    # Append additional content, if provided
    if [ -n "$content" ]; then
        echo -e "$content" >> "$dest_file"
    fi

    # Append the content of the source file to the destination file
    cat "$src_file" >> "$dest_file"
}

if [ "$#" -eq 0 ]; then
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
    case "$1" in        # Append the content of the decrypted "in" file to dec_debug.txt

        -mb)
            unit_flag="MB"
            shift
            ;;
        -m|--mode)
            shift
            encryption_mode="$1"
            shift
            ;;
        -t|--text)
            create_text_file=true  # Enable text file creation
            shift
            ;;
        -d|--debug)
            # Check if the file size is less than 1MB (in megabytes) or 1048576 bytes
            if [ "$unit_flag" == "MB" ] && [ "$file_size" -gt 1 ]; then
                echo "Error: Debug mode is only supported for files smaller than 1MB."
                exit 1
            elif [ "$unit_flag" != "MB" ] && [ "$file_size" -gt 1048576 ]; then
                echo "Error: Debug mode is only supported for files smaller than 1MB."
                exit 1
            fi
            debug_mode=true  # Enable debug mode
            shift
            ;;
        [0-9]*)
            # Check if the argument is numeric
            file_size="$1"
            shift
            ;;
        *)
            echo "Error: Invalid argument: $1"
            display_usage
            exit 1
            ;;
    esac
done



# Check if the unit is MB and convert to bytes if necessary
if [ "$unit_flag" == "MB" ]; then
    file_size=$(convert_to_bytes "$file_size")
fi

# Create either a random bytes file or a text file with random text
if [ "$create_text_file" = true ]; then
    # Create a text file with random text
    generate_random_text "$file_size" > "in"
else
    # Generate a random input file named "in" of the specified size
    head -c "$file_size" /dev/urandom > "in"
fi

# Display information about the chosen options
echo "Options chosen:"
if [ "$unit_flag" == "MB" ]; then
    echo "  File Size: $(convert_to_mb "$file_size")"
else
    echo "  File Size: $file_size bytes"
fi
echo "  Encryption Mode: $encryption_mode"
echo "  Debug Mode: $debug_mode"  # Display debug mode status
echo "  Create Text File: $create_text_file"  # Display text file creation status

# Calculate and store the MD5 checksum of the original "in" file
original_md5sum=$(md5sum "in" | awk '{print $1}')

# Create a temporary file for make output
make_output_file=$(mktemp)

if [ "$debug_mode" = true ]; then
    # Recompile and execute the program in encryption with debug flags (block logging is redirected to files)
    make CFLAGS="-DDEBUG -DQUIET -DSEQ" > "$make_output_file" 2>&1
    check_make_output "$make_output_file"
    { ./cfeistel enc -m "$encryption_mode" -i "in" -o "out"; } > "enc_debug.txt" 2>&1

    # Check if the "text" option is enabled and append the content of the generated "in" text file to enc_debug.txt
    if [ "$create_text_file" = true ]; then
        append_to_file "enc_debug.txt" "in" "\n\nContent of generated 'in' text file:"
    fi

    # Execute the program in decryption
    { ./cfeistel dec -m "$encryption_mode" -i "out" -o "in"; } > "dec_debug.txt" 2>&1

    # Check if the "text" option is enabled and append the content of the decrypted "in" text file to dec_debug.txt
    if [ "$create_text_file" = true ]; then
        append_to_file "dec_debug.txt" "in" "\n\nContent of decrypted 'in' file:"
    fi
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
