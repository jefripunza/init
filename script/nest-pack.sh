#!/bin/bash
# description: fast init NestJS project with user module and authorization with JWT
# example: curl -fsSL https://init.jefripunza.com/nest-pack.sh -o nest-pack.sh && bash nest-pack.sh my-project-name

set -e # Exit immediately if a command exits with a non-zero status
## $1 could be empty, so we need to disable this check
#set -u # Treat unset variables as an error and exit
set -o pipefail # Cause a pipeline to return the status of the last command that exited with a non-zero status

DATE=$(date +"%Y%m%d-%H%M%S")
CURRENT_USER=$USER
rm -rf nest-pack.sh

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
nest new $project_name --package-manager yarn

### ========================================================================== ###
###                               INSTALLATION                                 ###
### ========================================================================== ###

echo "Installing module..."

# masuk ke folder project
pushd $project_name

# buat variable array untuk module apa saja yang ingin ditambahkan custom
module_list=(
    "@nestjs/config"
    "@nestjs/microservices"
    "@nestjs/platform-express"
    "dotenv"
    "uuid"

    # auth
    "@nestjs/jwt"
    "@nestjs/passport"
    "bcrypt"
    "passport"
    "passport-jwt"

    "class-transformer"
    "class-validator"
    "reflect-metadata"
    # database
    "@nestjs/typeorm"
    "typeorm"
    "sqlite3"
)
module_list_dev=(
    "@types/passport-jwt"
    "@types/bcrypt"
    "@types/node"
)

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
nest generate guard auth
nest generate decorator auth


### ========================================================================== ###
###                               EXTRA FILES                                  ###
### ========================================================================== ###

echo "Generating extra files..."

# create constant.ts on ./src/constants.ts
echo "export type RoleCode = 'ADMIN' | 'CUSTOMER';" > src/constants.ts

# create user.entity.ts on ./src/user/user.entity.ts
echo "Creating user entity file..."
mkdir -p src/user
cat > src/user/user.entity.ts << 'EOL'
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;
}
EOL
echo "✓ Created user.entity.ts"

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
    
    # Create a Node.js script to handle the import path updates
    # This is much more reliable than complex shell script regex
    cat > update-imports.js << 'EOL'
const fs = require('fs');
const path = require('path');

// Get list of files from stdin (one file per line)
const files = fs.readFileSync(0, 'utf-8').trim().split('\n');

files.forEach(file => {
  console.log(`Processing ${file}`);
  
  // Get the directory relative to src
  const relDir = path.dirname(file).replace(/^src[\\/]?/, '');
  
  // Read the file content
  let content = fs.readFileSync(file, 'utf-8');
  let updated = false;
  
  // Replace imports with regex patterns
  // 1. Handle './something' imports
  if (content.match(/from ['"]\.\//)) {
    if (relDir === '.' || relDir === '') {
      // Root src directory - avoid double slash
      content = content.replace(/from (['"]).\/(.*?)\1/g, 'from $1@/$2$1');
    } else {
      // Nested directory
      content = content.replace(/from (['"]).\/(.*?)\1/g, `from $1@/${relDir}/$2$1`);
    }
    updated = true;
  }
  
  // 2. Handle '../something' imports
  if (content.match(/from ['"]\.\.\//)) {
    const parentDir = path.dirname(relDir) === '.' ? '' : path.dirname(relDir);
    
    // Extract the path after '../' and calculate the correct absolute path
    content = content.replace(/from (['"])..\/([^'"]+)\1/g, (match, quote, importPath) => {
      // Avoid double slashes by checking if parentDir is empty
      return `from ${quote}@/${parentDir ? parentDir + '/' : ''}${importPath}${quote}`;
    });
    updated = true;
  }
  
  // 3. Handle '../../something' imports
  if (content.match(/from ['"]\.\.\/.\.\//)) {
    // Go up two directory levels
    const parts = relDir.split('/');
    const grandParentDir = parts.length > 1 ? parts.slice(0, -2).join('/') : '';
    
    content = content.replace(/from (['"])..\/..\/(.*?)\1/g, (match, quote, importPath) => {
      // Avoid double slashes by checking if grandParentDir is empty
      return `from ${quote}@/${grandParentDir ? grandParentDir + '/' : ''}${importPath}${quote}`;
    });
    updated = true;
  }
  
  // Write the updated content back to the file
  fs.writeFileSync(file, content);
  
  if (updated) {
    console.log(`✓ Updated imports in ${file}`);
  } else {
    console.log(`No relative imports found or updated in ${file}`);
  }
});
EOL
    
    # Find all TypeScript files and pipe them to the Node.js script
    find src -type f -name "*.ts" | bun run update-imports.js
    
    # Clean up the temporary script
    rm -f update-imports.js
    
    echo "Updated import paths in all TypeScript files to use @/ alias"
else
    echo "Warning: src directory not found, skipping import path updates"
fi

### ========================================================================== ###
###                            NEW or REPLACEMENT                              ###
### ========================================================================== ###

echo "Replacing..."

# Function to create a new file or replace an existing one
new_or_replace() {
    local file_path="$1"
    local content="$2"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$file_path")"
    
    # Check if file exists
    if [ -f "$file_path" ]; then
        echo "Replacing existing file: $file_path"
    else
        echo "Creating new file: $file_path"
    fi
    
    # Write content to file
    echo "$content" > "$file_path"
    echo "✓ File operation completed: $file_path"
}

# new user entity
new_or_replace "./src/user/user.entity.ts" "import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';\n\n@Entity()\nexport class User {\n  @PrimaryGeneratedColumn()\n  id: number;\n\n  @Column({ unique: true })\n  email: string;\n\n  @Column()\n  password: string;\n}"

### ========================================================================== ###
###                                  TEST                                      ###
### ========================================================================== ###

echo "Testing..."

yarn build
yarn test

### ========================================================================== ###

echo "Done!"
popd
