import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Sign } from 'crypto';
import { Model } from 'mongoose';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';

@Injectable()
export class AuthService {
    constructor(@InjectModel(User.name) private UserModel: Model<User>) {}

    async signup(signupData: SignupDto){

        const { email, password, name, mobile } = signupData;
        const emailInUse = await this.UserModel.findOne({
            email: signupData.email,
        });

        if(emailInUse){
            throw new BadRequestException('Email already in use');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await this.UserModel.create({
            name,
            email,
            password: hashedPassword,
            mobile,
        });
    }

    async login(credentials: LoginDto){
        const { email, password } = credentials;

        const user = await this.UserModel.findOne({ email });

        if(!user){
            throw new UnauthorizedException("Wrong credentials");
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if(!passwordMatch){
            throw new UnauthorizedException("wrong credentials");
        }

        return{
            message: "success",
        }
    }
}
