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
    "joi"

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
###                               GENERATION                                   ###
### ========================================================================== ###

echo "Generating module..."

# remove git
rm -rf .git

# Function to create a new file or replace an existing one
generate() {
    local file_path="$1"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$file_path")"
    
    # Check if file exists
    if [ -f "$file_path" ]; then
        echo "Replacing existing file: $file_path"
    else
        echo "Creating new file: $file_path"
    fi
    
    # The content will be provided via heredoc from the caller
    cat > "$file_path"
    echo "✓ File operation completed: $file_path"
}

## >> Constants

# create constants
generate "./src/constants/index.ts" << 'EOL'
export type RoleCode = 'ADMIN' | 'USER';

export const ROLES = {
  ADMIN: 'ADMIN' as RoleCode,
  USER: 'USER' as RoleCode,
};
EOL






## >> Config

# create config.schema.ts
generate "./src/config/config.schema.ts" << 'EOL'
import * as Joi from 'joi';

export const configValidationSchema = Joi.object({
  // Node environment
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  
  // Server configuration
  PORT: Joi.number().default(3000),
  
  // Database configuration
  DB_TYPE: Joi.string().default('sqlite'),
  DB_HOST: Joi.string().when('DB_TYPE', {
    is: Joi.string().valid('postgres', 'mysql', 'mariadb'),
    then: Joi.string().required(),
    otherwise: Joi.string().optional(),
  }),
  DB_PORT: Joi.number().when('DB_TYPE', {
    is: Joi.string().valid('postgres', 'mysql', 'mariadb'),
    then: Joi.number().required(),
    otherwise: Joi.number().optional(),
  }),
  DB_USERNAME: Joi.string().when('DB_TYPE', {
    is: Joi.string().valid('postgres', 'mysql', 'mariadb'),
    then: Joi.string().required(),
    otherwise: Joi.string().optional(),
  }),
  DB_PASSWORD: Joi.string().when('DB_TYPE', {
    is: Joi.string().valid('postgres', 'mysql', 'mariadb'),
    then: Joi.string().required(),
    otherwise: Joi.string().optional(),
  }),
  DB_NAME: Joi.string().required(),
  DB_SYNCHRONIZE: Joi.boolean().default(true),
  
  // JWT configuration
  JWT_SECRET: Joi.string().required(),
  JWT_EXPIRES_IN: Joi.string().default('1h'),
  
  // Admin user seed configuration
  ADMIN_EMAIL: Joi.string().email().default('admin@example.com'),
  ADMIN_PASSWORD: Joi.string().min(6).default('admin123'),
});
EOL

# create config.service.ts
generate "./src/config/config.service.ts" << 'EOL'
import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
  constructor(private configService: NestConfigService) {}

  // Database configuration
  get dbType(): string {
    return this.configService.get<string>('DB_TYPE') || 'sqlite';
  }

  get dbHost(): string {
    return this.configService.get<string>('DB_HOST') || 'localhost';
  }

  get dbPort(): number {
    return this.configService.get<number>('DB_PORT') || 5432;
  }

  get dbUsername(): string {
    return this.configService.get<string>('DB_USERNAME') || 'postgres';
  }

  get dbPassword(): string {
    return this.configService.get<string>('DB_PASSWORD') || 'postgres';
  }

  get dbName(): string {
    return this.configService.get<string>('DB_NAME') || 'db.sqlite';
  }

  get dbSynchronize(): boolean {
    return this.configService.get<boolean>('DB_SYNCHRONIZE') || true;
  }

  // JWT configuration
  get jwtSecret(): string {
    return this.configService.get<string>('JWT_SECRET') || 'my-secret-key';
  }

  get jwtExpiresIn(): string {
    return this.configService.get<string>('JWT_EXPIRES_IN') || '1h';
  }

  // App configuration
  get port(): number {
    return this.configService.get<number>('PORT') || 3000;
  }

  get nodeEnv(): string {
    return this.configService.get<string>('NODE_ENV') || 'development';
  }

  get isProduction(): boolean {
    return this.nodeEnv === 'production';
  }

  get isDevelopment(): boolean {
    return this.nodeEnv === 'development';
  }

  get isTest(): boolean {
    return this.nodeEnv === 'test';
  }

  // Admin user seed configuration
  get adminEmail(): string {
    return this.configService.get<string>('ADMIN_EMAIL') || 'admin@example.com';
  }

  get adminPassword(): string {
    return this.configService.get<string>('ADMIN_PASSWORD') || 'admin123';
  }
}
EOL

# create config.module.ts
generate "./src/config/config.module.ts" << 'EOL'
import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { ConfigService } from '@/config/config.service';
import { configValidationSchema } from '@/config/config.schema';

@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.test', '.env'],
      validationSchema: configValidationSchema,
    }),
  ],
  providers: [ConfigService],
  exports: [ConfigService],
})
export class ConfigModule {}
EOL






## >> User

# create user.entity.ts
generate "./src/user/user.entity.ts" << 'EOL'
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';
import { RoleCode } from '@/constants';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password?: string;

  @Column({ default: 'user' })
  role: RoleCode; // admin, user
}
EOL

# create user.service.ts
generate "./src/user/user.service.ts" << 'EOL'
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '@/user/user.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) {}

  async create(email: string, password: string) {
    const user = this.userRepo.create({ email, password });
    return this.userRepo.save(user);
  }

  async findByEmail(email: string) {
    return this.userRepo.findOne({ where: { email } });
  }

  async findById(id: number) {
    return this.userRepo.findOne({ where: { id } });
  }

  async update(user: User) {
    return this.userRepo.save(user);
  }
}
EOL

# create user.service.spec.ts
generate "./src/user/user.service.spec.ts" << 'EOL'
import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from '@/user/user.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '@/user/user.entity';
import { Repository } from 'typeorm';

describe('UserService', () => {
  let service: UserService;
  let userRepository: Repository<User>;

  const mockUserRepository = {
    create: jest.fn(),
    save: jest.fn(),
    findOne: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
EOL

# create user.decorator.ts
generate "./src/user/user.decorator.ts" << 'EOL'
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetUser = createParamDecorator((data, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.user;
});
EOL

# create user.controller.ts
generate "./src/user/user.controller.ts" << 'EOL'
import { Controller, Get } from '@nestjs/common';
import { UseAuth } from '@/auth/auth.decorator';
import { GetUser } from '@/user/user.decorator';
import { User } from '@/user/user.entity';

@Controller('api/user')
export class UserController {
  @UseAuth("ADMIN")
  @Get('me')
  getMe(@GetUser() user: User) {
    delete user.password;
    return user;
  }
}
EOL

# create user.controller.spec.ts
generate "./src/user/user.controller.spec.ts" << 'EOL'
import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from '@/user/user.controller';
import { AuthGuard } from '@/auth/auth.guard';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '@/user/user.service';
import { Reflector } from '@nestjs/core';

describe('UserController', () => {
  let controller: UserController;

  const mockJwtService = {
    verifyAsync: jest.fn(),
  };

  const mockUserService = {
    findById: jest.fn(),
  };

  const mockReflector = {
    getAllAndOverride: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
        {
          provide: UserService,
          useValue: mockUserService,
        },
        {
          provide: Reflector,
          useValue: mockReflector,
        },
      ],
    })
    .overrideGuard(AuthGuard)
    .useValue({ canActivate: jest.fn(() => true) })
    .compile();

    controller = module.get<UserController>(UserController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
EOL

# replace user.module.ts
generate "./src/user/user.module.ts" << 'EOL'
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '@/user/user.entity';
import { UserService } from '@/user/user.service';
import { UserController } from '@/user/user.controller';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService],
})
export class UserModule {}
EOL







## >> Seed

# replace seed.service.ts
generate "./src/seed/seed.service.ts" << 'EOL'
import { Injectable, OnModuleInit } from '@nestjs/common';
import { UserService } from '@/user/user.service';
import { ConfigService } from '@/config/config.service';
import * as bcrypt from 'bcrypt';
import { ROLES } from '@/constants';

@Injectable()
export class SeedService implements OnModuleInit {
  constructor(
    private userService: UserService,
    private configService: ConfigService,
  ) {}

  async onModuleInit() {
    await this.seedAdmin();
  }

  async seedAdmin() {
    try {
      // Check if admin exists
      const adminEmail = this.configService.adminEmail;
      const existingAdmin = await this.userService.findByEmail(adminEmail);

      if (!existingAdmin) {
        console.log('Admin user not found. Creating admin user...');

        // Create admin with hashed password
        const password = this.configService.adminPassword;
        const hashedPassword = await bcrypt.hash(password, 10);

        const admin = await this.userService.create(adminEmail, hashedPassword);

        // Update role to admin
        admin.role = ROLES.ADMIN;
        await this.userService.update(admin);

        console.log('Admin user created successfully');
        console.log(`Email: ${adminEmail}`);
        console.log(`Password: ${password}`);
      } else {
        console.log('Admin user already exists');
      }
    } catch (error) {
      console.error('Failed to seed admin user:', error);
    }
  }
}
EOL

# replace seed.module.ts
generate "./src/seed/seed.module.ts" << 'EOL'
import { Module } from '@nestjs/common';
import { SeedService } from '@/seed/seed.service';
import { UserModule } from '@/user/user.module';
import { ConfigModule } from '@/config/config.module';

@Module({
  imports: [UserModule, ConfigModule],
  providers: [SeedService],
})
export class SeedModule {}

EOL










## >> Auth

# create auth.guard.ts
generate "./src/auth/auth.guard.ts" << 'EOL'
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '@/user/user.service';
import { ROLES_KEY } from '@/auth/auth.decorator';
import { RoleCode } from '@/constants';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private userService: UserService,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.getAllAndOverride<RoleCode[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const request = context.switchToHttp().getRequest<Request>();
    const authHeader = request.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid token');
    }

    const token = authHeader.split(' ')[1];

    try {
      const payload = await this.jwtService.verifyAsync(token);
      const user = await this.userService.findById(payload.sub);

      if (!user) throw new UnauthorizedException('User not found');

      // Inject user ke request
      request.user = user;

      // Jika tidak ada roles spesifik, berarti cukup login saja
      if (!roles || roles.length === 0) return true;

      if (!roles.includes(user.role)) {
        throw new ForbiddenException('You do not have permission');
      }

      return true;
    } catch (e) {
      throw new UnauthorizedException(e.message);
    }
  }
}
EOL

# create auth.guard.spec.ts
generate "./src/auth/auth.guard.spec.ts" << 'EOL'
import { AuthGuard } from '@/auth/auth.guard';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { UserService } from '@/user/user.service';
import { Test } from '@nestjs/testing';

describe('AuthGuard', () => {
  let guard: AuthGuard;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuthGuard,
        {
          provide: JwtService,
          useValue: {
            verifyAsync: jest.fn(),
          },
        },
        {
          provide: UserService,
          useValue: {
            findById: jest.fn(),
          },
        },
        {
          provide: Reflector,
          useValue: {
            getAllAndOverride: jest.fn(),
          },
        },
      ],
    }).compile();

    guard = moduleRef.get<AuthGuard>(AuthGuard);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });
});
EOL

# create auth.decorator.ts
generate "./src/auth/auth.decorator.ts" << 'EOL'
import { applyDecorators, UseGuards, SetMetadata } from '@nestjs/common';
import { AuthGuard } from '@/auth/auth.guard';
import { RoleCode } from '@/constants';

export const ROLES_KEY = 'roles';

export function UseAuth(...roles: RoleCode[]) {
  return applyDecorators(
    SetMetadata(ROLES_KEY, roles),
    UseGuards(AuthGuard),
  );
}
EOL

# create auth.service.ts
generate "./src/auth/auth.service.ts" << 'EOL'
import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '@/user/user.service';
import { ConfigService } from '@/config/config.service';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async register(email: string, password: string) {
    // check if email exist
    const user = await this.userService.findByEmail(email);
    if (user) {
      throw new BadRequestException('Email already exists');
    }

    const hashed = await bcrypt.hash(password, 10);
    await this.userService.create(email, hashed);
    return {
      message: 'User registered successfully',
    };
  }

  async login(email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    if (!user || !(await bcrypt.compare(password, user?.password as string))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const token = this.jwtService.sign(
      { sub: user.id },
      {
        secret: this.configService.jwtSecret,
        expiresIn: this.configService.jwtExpiresIn,
      },
    );

    return {
      token,
      user,
      message: 'User logged in successfully',
    };
  }
}
EOL

# create auth.service.spec.ts
generate "./src/auth/auth.service.spec.ts" << 'EOL'
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '@/auth/auth.service';
import { UserService } from '@/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@/config/config.service';

describe('AuthService', () => {
  let service: AuthService;
  let userService: UserService;
  let jwtService: JwtService;
  let configService: ConfigService;

  const mockUserService = {
    findByEmail: jest.fn(),
    create: jest.fn(),
    findById: jest.fn(),
  };

  const mockJwtService = {
    sign: jest.fn(),
    verify: jest.fn(),
    verifyAsync: jest.fn(),
  };

  const mockConfigService = {
    jwtSecret: 'test-secret',
    jwtExpiresIn: '1h',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UserService,
          useValue: mockUserService,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userService = module.get<UserService>(UserService);
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
EOL

# create auth.controller.ts
generate "./src/auth/auth.controller.ts" << 'EOL'
import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import { AuthService } from '@/auth/auth.service';

@Controller('/api/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('v1/register')
  register(@Body() body: { email: string; password: string }) {
    return this.authService.register(body.email, body.password);
  }

  @Post('v1/login')
  @HttpCode(200)
  login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }
}
EOL

# create auth.controller.spec.ts
generate "./src/auth/auth.controller.spec.ts" << 'EOL'
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from '@/auth/auth.controller';
import { AuthService } from '@/auth/auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;

  const mockAuthService = {
    register: jest.fn(),
    login: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
EOL

# create auth.module.ts
generate "./src/auth/auth.module.ts" << 'EOL'
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from '@/auth/auth.service';
import { AuthController } from '@/auth/auth.controller';
import { UserModule } from '@/user/user.module';
import { ConfigModule } from '@/config/config.module';

@Module({
  imports: [
    UserModule,
    JwtModule,
    ConfigModule,
  ],
  providers: [AuthService],
  controllers: [AuthController],
  exports: [],
})
export class AuthModule {}
EOL







## >> App

# replace app.module.ts
generate "./src/app.module.ts" << 'EOL'
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

import { AppController } from '@/app.controller';
import { AppService } from '@/app.service';

import { UserModule } from '@/user/user.module';
import { AuthModule } from '@/auth/auth.module';
import { SeedModule } from '@/seed/seed.module';
import { ConfigModule } from '@/config/config.module';
import { ConfigService } from '@/config/config.service';

@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: configService.dbType as any,
        host: configService.dbHost,
        port: configService.dbPort,
        username: configService.dbUsername,
        password: configService.dbPassword,
        database: configService.dbName,
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: configService.dbSynchronize,
      }),
    }),
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secretOrPrivateKey: configService.jwtSecret,
        signOptions: { expiresIn: configService.jwtExpiresIn },
      }),
    }),
    UserModule,
    AuthModule,
    SeedModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
EOL






## >> Test

# replace app.e2e-spec.ts
generate "./test/app.e2e-spec.ts" << 'EOL'
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';

import { App } from 'supertest/types';
import { AppModule } from '@/app.module';

const pwd = __dirname;
const root = path.join(pwd, '../');

// delete db.sqlite
if (fs.existsSync(`${root}/db.sqlite`)) {
  fs.unlinkSync(`${root}/db.sqlite`);
  console.log('db.sqlite deleted');
}

describe('AppController (e2e)', () => {
  let app: INestApplication<App>;
  let token_admin: string;
  let token_user: string;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });

  // login by admin
  it('/api/auth/v1/login (POST) admin', () => {
    return request(app.getHttpServer())
      .post('/api/auth/v1/login')
      .send({ email: 'admin@example.com', password: 'admin123' })
      .expect(200)
      .then((res) => {
        token_admin = res.body.token;
      });
  });

  // login by user if unregister
  it('/api/auth/v1/login (POST) user', () => {
    return request(app.getHttpServer())
      .post('/api/auth/v1/login')
      .send({ email: 'john@doe.com', password: 'everything' })
      .expect(401);
  });

  // register by user
  it('/api/auth/v1/register (POST)', () => {
    return request(app.getHttpServer())
      .post('/api/auth/v1/register')
      .send({ email: 'john@doe.com', password: 'everything' })
      .expect(201);
  });

  // login by user if register
  it('/api/auth/v1/login (POST)', () => {
    return request(app.getHttpServer())
      .post('/api/auth/v1/login')
      .send({ email: 'john@doe.com', password: 'everything' })
      .expect(200)
      .then((res) => {
        token_user = res.body.token;
        console.log('token_user: ', token_user);
      });
  });

  // get me by admin
  it('/api/user/me (GET)', () => {
    return request(app.getHttpServer())
      .get('/api/user/me')
      .set('Authorization', `Bearer ${token_admin}`)
      .expect(200);
  });

  // get me by user
  it('/api/user/me (GET)', () => {
    return request(app.getHttpServer())
      .get('/api/user/me')
      .set('Authorization', `Bearer ${token_user}`)
      .expect(401);
  });
});
EOL

# replace jest-e2e.json
generate "./test/jest-e2e.json" << 'EOL'
{
  "moduleFileExtensions": ["js", "json", "ts"],
  "rootDir": ".",
  "testEnvironment": "node",
  "testRegex": ".e2e-spec.ts$",
  "transform": {
    "^.+\\.(t|j)s$": "ts-jest"
  },
  "moduleNameMapper": {
    "^@/(.*)$": "<rootDir>/../src/$1"
  }
}
EOL

# create .env.example
generate ".env.example" << 'EOL'
# Node environment: development, production, test
NODE_ENV=

# Server configuration
PORT=

# Database configuration
DB_TYPE=
# DB_HOST=localhost  # Required for postgres, mysql, mariadb
# DB_PORT=5432       # Required for postgres, mysql, mariadb
# DB_USERNAME=postgres  # Required for postgres, mysql, mariadb
# DB_PASSWORD=postgres  # Required for postgres, mysql, mariadb
DB_NAME=
DB_SYNCHRONIZE=

# JWT configuration
JWT_SECRET=
JWT_EXPIRES_IN=

# Admin user seed configuration
ADMIN_EMAIL=
ADMIN_PASSWORD=
EOL

# create .env.test
generate ".env.test" << 'EOL'
NODE_ENV=test
JWT_SECRET=test-secret-key
JWT_EXPIRES_IN=1h
DB_TYPE=sqlite
DB_NAME=db.sqlite
DB_SYNCHRONIZE=true
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=admin123
EOL

### ========================================================================== ###
###                                  TEST                                      ###
### ========================================================================== ###

echo "Testing..."

yarn build
yarn test
yarn test:e2e

### ========================================================================== ###

echo "Done!"
popd
