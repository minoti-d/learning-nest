import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { throws } from 'assert';
import { JwtService } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
//import { User, Bookmark } from '@prisma/client';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService, 
        private jwt: JwtService,
        private config: ConfigService){}
    
    async signup(dto: AuthDto){
        const hash = await argon.hash(dto.password); // await the result of argon2.hash
        // save the user in the db
        try{
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                }
            });
            
            return this.signedToken(user.id, user.email)
        }
        catch(error){
            if (error instanceof PrismaClientKnownRequestError){
                if (error.code ==='P2002') //code for new record with data of an existing field
                {
                    throw new ForbiddenException('Credentials Taken')
                }
            }
            throw error
        }
        //return {msg: 'Signed Uppp'}
    }
    
    async signin(dto: AuthDto) {
        const user = await this.prisma.user.findFirst({
            where: {
                email: dto.email,
            },
        });
    
        if (!user) {
            throw new ForbiddenException('Credentials incorrect');
        };
    
        //comparing password
        const pwMatches = await argon.verify(user.hash, dto.password)

        if(!pwMatches) throw new ForbiddenException('Credentials Incorrect')
        
        return this.signedToken(user.id, user.email);
        //return { msg: 'Signed in' };
    }

    async signedToken(
        userId: number, 
        email: string): Promise<{access_token: string}>{
            const payload = {
                sub: userId,
                //writing sub is a convention oif jwd for a unique identifier
                email
            }

            const secret = this.config.get('JWT_SECRET')

            // const token = await this.jwt.signAsync(
            //     payload, 
            //     {
            //     expiresIn: '15m',
            //     secret: secret
            // })

            //first argument takes what we want to encrypt in JWT
            //second can have various parameters like it in expires in waht time or what is the secret
            //secret parameter is compulsory

            return {
                access_token: await this.jwt.signAsync(payload, {expiresIn : '15m', secret: secret}),
              };
        
    }
    
}
