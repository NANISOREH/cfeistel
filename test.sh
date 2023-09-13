#!/bin/bash

# Initialize variables with default values
file_size=0  
unit_flag="B"  
encryption_mode="ecb" 
debug_mode=false  
parallel_debug_mode=false
enc_key="secretkey"
dec_key="secretkey"
cflags="-DQUIET"
create_text_file=false  

# Converts megabytes to bytes
convert_to_bytes() {
    local mb="$1"
    echo "$((mb * 1024 * 1024))"
}

# Converts bytes to megabytes
convert_to_mb() {
    local bytes="$1"
    echo "$((bytes / 1024 / 1024)) MB"
}

# Generates a file containing random text of a specified length
generate_random_text() {
    # Base case: if the desired length is 0 or negative, return an empty string
    if [ "$file_size" -le 0 ]; then
        echo ""
        return
    fi

    local output_file="$1"
    local current_size=0

    # Loop until the current size reaches the desired total size
    while [ "$current_size" -lt "$file_size" ]; do
        # Generate a random ASCII character starting from the content of the $RANDOM variable
        random_char=$(printf \\$(printf '%o' "$((RANDOM % 95 + 32))"))

        # Check if adding the character exceeds the desired total size
        if [ "$((current_size + char_size))" -le "$file_size" ]; then
            printf "%s" "$random_char" >> "$output_file"  # Append the character to the file
            current_size=$((current_size + 1))  # Update the current size
        fi
    done
}

# Generates a file by repeating the same 16 characters block
generate_repeated_text() {
    local output_file="$1"
    local block_size=16
    local repeated_block=""

    # Generate a random repeated block of 16 bytes
    for _ in $(seq 1 "$block_size"); do
        repeated_block+=$(printf \\$(printf '%o' "$((RANDOM % 95 + 32))"))
    done

    # Calculate how many times the block should be repeated to reach the total size
    local repetitions=$((file_size / block_size))

    # Append the repeated block to the output file
    for _ in $(seq 1 "$repetitions"); do
        echo -n "$repeated_block" >> "$output_file"
    done
}

# Generates a file by repeating the same 16 bytes block
generate_repeated_data() {
    local output_file="$1"
    local random_block=""   

    # Generate a random 16-byte block
    random_block=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null)

    # Repeat the random 16-byte block until it matches $file_size exactly
    current_size=0
    while [ "$current_size" -lt "$file_size" ]; do
        echo -n "$random_block" >> "in"
        current_size=$((current_size + 16))
    done

    # Trim the file to match $file_size exactly
    truncate -s "$file_size" "in"
}

function display_usage() {
    echo "Usage: test.sh [options]"
    echo "Options:"
    echo "  -mb                  Use megabytes as unit for file size (default is bytes)"
    echo "  -m, --mode <mode>    Encryption mode (e.g., -m encrypt)"
    echo "  -k, --key <key>      Encryption and decryption key"
    echo "  -ek, --enckey <key>  Encryption key"
    echo "  -dk, --deckey <key>  Decryption key"
    echo "  -t, --text           Create a text file (size limit: 1MB)"
    echo "  -d, --debug          Enable debug mode (size limit: 1MB)"
    echo "  -dp, --debug-parallel Enable parallel debug mode (size limit: 1MB)"
    echo "  -r, --repeat         Enable repeated block mode"
    echo "  <file_size>          File size in bytes (numeric argument)"
}

# Appends the content of one file to another
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

# Checks if the make command produced errors or warnings
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

sort_blocks() {
    file="$1"

    # Temporary file
    temp_file="temp"

    # Initialize an associative array to store blocks by block number
    declare -A blocks

    # Initialize variables
    current_block=""
    in_block=false
    current_thread=""
    delimiter=""

    # Open input file for reading
    exec 3< "$file"

    while IFS= read -r line <&3; do
        if [[ $line =~ ^=+$ ]]; then
        # Delimiter line
        delimiter="$line"
        elif [[ $line =~ ^block[[:space:]]([0-9]+)[[:space:]]processed[[:space:]]by[[:space:]]the[[:space:]]thread[[:space:]]([0-9]+) ]]; then
        # Block header line
        block_number="${BASH_REMATCH[1]}"
        current_thread="${BASH_REMATCH[2]}"
        in_block=true
        current_block="$delimiter\nBlock $block_number processed by the thread $current_thread\n"
        elif [[ $line =~ ^=+$ && $in_block == true ]]; then
        # End of block
        in_block=false
        blocks["$block_number:$current_thread"]+="$current_block$line"
        current_block=""
        delimiter=""
        elif [ "$in_block" == true ]; then
        # Inside block, append line
        current_block+="$line\n"
        fi
    done

    # Close input file
    exec 3<&-

    # Sort the blocks by block number and thread number
    sorted_block_numbers=($(echo "${!blocks[@]}" | tr ' ' '\n' | sort -t':' -k1,1n -k2,2n))

    # Write the sorted blocks to the temporary file, preserving delimiters and spacing
    for block_info in "${sorted_block_numbers[@]}"; do
        IFS=':' read -r block_number thread_number <<< "$block_info"
        echo -e "${blocks[$block_info]}" >> "$temp_file"
    done

    # Replace the original file with the sorted content
    mv "$temp_file" "$file"
}



if [ "$#" -eq 0 ]; then
    display_usage
    exit 1
fi

# Process command line arguments
while [ "$#" -gt 0 ]; do
    case "$1" in      
        -mb)
            unit_flag="MB"
            shift
            ;;
        -m|--mode)
            shift
            encryption_mode="$1"
            shift
            ;;
        -k|--key)
            shift
            enc_key="$1"
            dec_key="$1"
            shift
            ;;
        -dk|--deckey)
            shift
            dec_key="$1"
            shift
            ;;
        -ek|--enckey)
            shift
            enc_key="$1"
            shift
            ;;
        -t|--text)
            # Check if the file size is less than 1MB (in megabytes) or 1048576 bytes
            if [ "$unit_flag" == "MB" ] && [ "$file_size" -gt 1 ]; then
                echo "Error: Text mode is only supported for files smaller than 1MB."
                exit unction to check1
            elif [ "$unit_flag" != "MB" ] && [ "$file_size" -gt 1048576 ]; then
                echo "Error: Text mode is only supported for files smaller than 1MB."
                exit 1
            fi
            create_text_file=true  # Enable text file creation
            shift
            ;;
        -d|--debug)
            if [ "$debug_parallel_mode" == true ]; then
                echo "Error: -d and -dp are mutually exclusive."
                exit 1
            fi
            # Check if the file size is less than 1MB (in megabytes) or 1048576 bytes
            if [ "$unit_flag" == "MB" ] && [ "$file_size" -gt 1 ]; then
                echo "Error: Debug mode is only supported for files smaller than 1MB."
                exit 1
            elif [ "$unit_flag" != "MB" ] && [ "$file_size" -gt 1048576 ]; then
                echo "Error: Debug mode is only supported for files smaller than 1MB."
                exit 1
            fi
            debug_mode=true  # Enable debug mode
            cflags="-DDEBUG -DQUIET -DSEQ"
            shift
            ;;
        -dp|--debug-parallel)
            if [ "$debug_mode" == true ]; then
                echo "Error: -d and -dp are mutually exclusive."
                exit 1
            fi
            # Check if the file size is less than 1MB (in megabytes) or 1048576 bytes
            if [ "$unit_flag" == "MB" ] && [ "$file_size" -gt 1 ]; then
                echo "Error: Debug mode is only supported for files smaller than 1MB."
                exit 1
            elif [ "$unit_flag" != "MB" ] && [ "$file_size" -gt 1048576 ]; then
                echo "Error: Debug mode is only supported for files smaller than 1MB."
                exit 1
            fi
            parallel_debug_mode=true  # Enable debug mode
            cflags="-DDEBUG -DQUIET"
            shift
            ;;
        -r|--repeat)
            repeated_mode=true  # Enable repeated block mode
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

# Creates a file, choosing whether it should be random or repeated, text or arbitrary data
if [ "$create_text_file" = true ]; then
    if [ "$repeated_mode" = true ]; then
        # Create a text file with repeated blocks of 16 bytes
        generate_repeated_text "in"
    else
        # Create a random text file of the specified size
        generate_random_text "in"
    fi
else
    if [ "$repeated_mode" = true ]; then
        generate_repeated_data "in"
    else
        # Generate a random input file named "in" of the specified size
        dd if=/dev/urandom of="in" bs="$file_size" count=1 2>/dev/null
    fi
fi

# Displays information about the chosen options
echo "Options chosen:"
if [ "$unit_flag" == "MB" ]; then
    echo "  File Size: $(convert_to_mb "$file_size")"
else
    echo "  File Size: $file_size bytes"
fi
echo "  Encryption Mode: $encryption_mode"
echo "  Debug Mode: $debug_mode" 
echo "  Text Mode: $create_text_file" 
echo "  Encryption Key: $enc_key" 
echo "  Decryption Key: $dec_key" 

# Calculate and store the MD5 checksum of the original "in" file
original_md5sum=$(md5sum "in" | awk '{print $1}')

# Create a temporary file for make output
make_output_file=$(mktemp)

# Recompile and execute the program in encryption with debug flags (block logging is redirected to files)
# The make output is redirected to a temp file and then grepped to only show relevant lines
if [ "$debug_mode" = true ] || [ "$parallel_debug_mode" = true ]; then
    make CFLAGS="$cflags" > "$make_output_file" 2>&1
    check_make_output "$make_output_file"
    { ./cfeistel enc -m "$encryption_mode" -k "$enc_key" -i "in" -o "out"; } > "enc_debug.txt" 2>&1

    # Check if the "text" option is enabled and append the content of the generated "in" text file to enc_debug.txt
    if [ "$create_text_file" = true ]; then
        append_to_file "enc_debug.txt" "in" "\n\nContent of generated 'in' text file:"
        #sort_blocks "enc_debug.txt"
    fi

    # Execute the program in decryption
    { ./cfeistel dec -m "$encryption_mode" -k "$dec_key" -i "out" -o "in"; } > "dec_debug.txt" 2>&1

    # Check if the "text" option is enabled and append the content of the decrypted "in" text file to dec_debug.txt
    if [ "$create_text_file" = true ]; then
        append_to_file "dec_debug.txt" "in" "\n\nContent of decrypted 'in' file:"
        #sort_blocks "dec_debug.txt"
    fi
else
    # Recompile and execute the program in encryption and decryption with default flags
    # The make output is redirected to a temp file and then grepped to only show relevant lines
    make CFLAGS="$cflags" > "$make_output_file" 2>&1
    check_make_output "$make_output_file"
    ./cfeistel enc -m "$encryption_mode" -k "$enc_key" -i "in" -o "out"
    ./cfeistel dec -m "$encryption_mode" -k "$dec_key" -i "out" -o "in"
fi

# Calculate and store the MD5 checksum of the decrypted "in" file
decrypted_md5sum=$(md5sum "in" | awk '{print $1}')

# Check if the MD5 checksums match
if [ "$original_md5sum" == "$decrypted_md5sum" ]; then
    echo -e "\e[32m\nEncryption and decryption successful. MD5 checksums match.\n\e[0m" 
else
    echo -e "\e[31m\nError: MD5 checksums do not match. Encryption or decryption failed.\n\e[0m"  
fi


# Clean up temporary files
rm "in" "out" "cfeistel"

exit 0