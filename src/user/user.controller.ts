import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from 'src/auth/decorator/get-user.decorator';
//import { AuthGuard } from '@nestjs/passport';
import { JwtGuard } from 'src/auth/guard';


interface CustomRequest extends Request {
    user: any; // Adjust the type of 'user' based on your actual user object type
  }
@UseGuards(JwtGuard)
@Controller('users')
export class UserController {  
    @Get('me')
    getMe(@GetUser() user: User){
        return user;
    }
}
