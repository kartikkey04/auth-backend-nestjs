import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Sign } from 'crypto';
import { Model } from 'mongoose';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4} from 'uuid';

@Injectable()
export class AuthService {
    constructor(@InjectModel(User.name) private UserModel: Model<User>,
                @InjectModel(RefreshToken.name) private RefreshTokenModel: Model<RefreshToken>,
                private jwtService: JwtService,
            ) {}

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

        return this.generateUserTokens(user._id);
    }

    async generateUserTokens(userId){
        const accessToken = this.jwtService.sign({userId},{expiresIn: '1h'});
        const refreshToken = uuidv4();
        return{
            accessToken,
            refreshToken
        };
    }
}
