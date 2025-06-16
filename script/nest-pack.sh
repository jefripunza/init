#!/bin/bash
# description: fast init NestJS project with user module and authorization with JWT
# example: curl -fsSL https://init.jefripunza.com/nest-pack.sh -o nest-pack.sh && bash nest-pack.sh my-project-name

set -e # Exit immediately if a command exits with a non-zero status
## $1 could be empty, so we need to disable this check
#set -u # Treat unset variables as an error and exit
set -o pipefail # Cause a pipeline to return the status of the last command that exited with a non-zero status

DATE=$(date +"%Y%m%d-%H%M%S")
CURRENT_USER=$USER

### ========================================================================== ###
###                               INITIALIZATION                               ###
### ========================================================================== ###

echo "Initializing..."

### check apakah di command ada "bun", kalau belum ada di install
if ! command -v bun &> /dev/null; then
    echo "bun not found, installing..."
    curl -fsSL https://bun.sh/install | bash
fi

# check apakah di command ada "yarn", kalau belum ada di install
if ! command -v yarn &> /dev/null; then
    echo "yarn not found, installing..."
    bun install -g yarn
fi

# check apakah di command ada "pnpm", kalau belum ada di install
if ! command -v pnpm &> /dev/null; then
    echo "pnpm not found, installing..."
    bun install -g pnpm
fi

### ========================================================================== ###
###                             CREATE PROJECT                                 ###
### ========================================================================== ###

echo "Creating project..."

### check apakah di command ada "nest", kalau belum ada di install
if ! command -v nest &> /dev/null; then
    echo "nest not found, installing..."
    bun install -g @nestjs/cli
fi

if [ -z "$1" ]; then
    echo "Please provide a project name"
    exit 1
fi
project_name=$1
nest new $project_name

### ========================================================================== ###
###                               INSTALLATION                                 ###
### ========================================================================== ###

echo "Installing module..."

# masuk ke folder project
pushd $project_name

# buat variable array untuk module apa saja yang ingin ditambahkan custom
module_list=("@nestjs/config" "@nestjs/jwt" "@nestjs/microservices" "@nestjs/passport" "@nestjs/platform-express" "@nestjs/typeorm" "bcrypt" "class-transformer" "class-validator" "dotenv" "passport" "passport-jwt" "reflect-metadata" "rxjs" "typeorm" "uuid")
module_list_dev=("@types/bcrypt")

# loop array dan install module
for module in "${module_list[@]}"; do
    bun install $module
done

# loop array dan install module dev
for module in "${module_list_dev[@]}"; do
    bun install --dev $module
done

### ========================================================================== ###
###                               GENERATION                                   ###
### ========================================================================== ###

echo "Generating module..."

# remove git
rm -rf .git

# full package for User
nest generate module user
nest generate controller user
nest generate service user

# full package for auth
nest generate module auth
nest generate controller auth
nest generate service auth


### ========================================================================== ###
###                               EXTRA FILES                                  ###
### ========================================================================== ###

echo "Generating extra files..."

# create constant.ts on ./src/constants.ts
echo "export type RoleCode = 'ADMIN' | 'CUSTOMER';" > src/constants.ts

### ========================================================================== ###
###                               REVISION FILES                               ###
### ========================================================================== ###

echo "Revision files..."

# tsconfig.json input paths menjadi @/*
# Use jq to update tsconfig.json with paths configuration
if command -v jq &> /dev/null; then
    # If jq is available, use it to properly update the JSON
    jq '.compilerOptions.paths = {"@/*": ["src/*"]}' tsconfig.json > tsconfig.tmp.json && mv tsconfig.tmp.json tsconfig.json
    echo "Updated tsconfig.json with paths configuration using jq"
else
    # Fallback to sed if jq is not available
    # This is less reliable but works in many cases
    sed -i 's/"compilerOptions": {/"compilerOptions": {\n    "paths": {\n      "@\/*": ["src\/*"]\n    },/g' tsconfig.json
    echo "Updated tsconfig.json with paths configuration using sed"
fi

# Update package.json to add moduleNameMapper in Jest configuration
if command -v jq &> /dev/null; then
    # If jq is available, use it to properly update the JSON
    jq '.jest.moduleNameMapper = {"^@/(.*)$": "<rootDir>/../src/$1"}' package.json > package.tmp.json && mv package.tmp.json package.json
    echo "Updated package.json with Jest moduleNameMapper configuration using jq"
else
    # Fallback to sed if jq is not available
    # This approach is less reliable but works in many cases
    sed -i 's/"jest": {/"jest": {\n    "moduleNameMapper": {\n      "\^@\/\(.*\)\$": "<rootDir>\/..\/src\/\$1"\n    },/g' package.json
    echo "Updated package.json with Jest moduleNameMapper configuration using sed"
fi

### ========================================================================== ###
###                               IMPORT ALIAS                                 ###
### ========================================================================== ###

echo "Updating import paths to use @/ alias..."

# Find all TypeScript files in the src directory
if [ -d "src" ]; then
    echo "Finding TypeScript files..."
    
    # Process each TypeScript file recursively
    find src -type f -name "*.ts" | while read -r file; do
        echo "Processing $file"
        
        # Get the current file's directory relative to src
        # This helps us calculate the correct import paths
        rel_dir=$(dirname "$file" | sed 's|^src/||')
        
        # Create a temporary file
        temp_file="${file}.tmp"
        
        # Process the file line by line to handle imports correctly
        while IFS= read -r line; do
            # Check if this line contains an import with relative path
            if [[ $line =~ from[[:space:]]*["\']\./|from[[:space:]]*["\']\.\./ ]]; then
                # Case 1: Handle './file' imports
                if [[ $line =~ from[[:space:]]*["\']\.\/([^"\'\.]+) ]]; then
                    # For same directory imports, use current directory in path
                    if [ "$rel_dir" = "." ]; then
                        # Root src directory
                        line=$(echo "$line" | sed "s|from[[:space:]]*[\"']\./\([^\"']*\)[\"']|from \"@/\1\"|g")
                    else
                        # Nested directory - include the directory in the path
                        line=$(echo "$line" | sed "s|from[[:space:]]*[\"']\./\([^\"']*\)[\"']|from \"@/$rel_dir/\1\"|g")
                    fi
                
                # Case 2: Handle '../file' imports (go up one directory)
                elif [[ $line =~ from[[:space:]]*["\']\.\./ ]]; then
                    # Calculate the target directory by going up one level
                    parent_dir=$(dirname "$rel_dir")
                    if [ "$parent_dir" = "." ]; then
                        parent_dir=""
                    fi
                    
                    # Extract the imported file/module name
                    import_name=$(echo "$line" | sed -E "s|.*from[[:space:]]*[\"']\.\./([^\"']+)[\"'].*|\1|")
                    
                    # Replace with @/ path
                    if [ -z "$parent_dir" ]; then
                        line=$(echo "$line" | sed "s|from[[:space:]]*[\"']\.\./[^\"']*[\"']|from \"@/$import_name\"|")
                    else
                        line=$(echo "$line" | sed "s|from[[:space:]]*[\"']\.\./[^\"']*[\"']|from \"@/$parent_dir/$import_name\"|")
                    fi
                fi
            fi
            
            # Write the processed line to temp file
            echo "$line" >> "$temp_file"
        done < "$file"
        
        # Replace original with processed file
        mv "$temp_file" "$file"
        
        # Check if any replacements were made
        if grep -q "from ['\"]@\/" "$file"; then
            echo "✓ Updated imports in $file"
        else
            echo "No relative imports found or updated in $file"
        fi
    done
    
    echo "Updated import paths in all TypeScript files to use @/ alias"
else
    echo "Warning: src directory not found, skipping import path updates"
fi

### ========================================================================== ###
###                                  TEST                                      ###
### ========================================================================== ###

echo "Testing..."

yarn build
yarn test

### ========================================================================== ###

echo "Done!"
popd
rm -rf nest-pack.sh
