import {
  BaseEntity,
  BeforeInsert,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from "typeorm";
import { IsBoolean, IsEmail, IsString, Length } from "class-validator";
import { Exclude } from "class-transformer";

export enum RoleType {
  USER = "user",
  PUBLISHER = "publisher",
  ADMIN = "admin",
}

@Entity({ name: "users" })
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: string;

  // Change entity name for migration checking:
  @Column({ unique: true })
  @IsString()
  name: string;

  @Column({ unique: true })
  @IsEmail()
  @IsString()
  email: string;

  @Column({ default: false })
  isTfaEnabled: boolean;

  @Column({ nullable: true })
  tfaSecret: string;

  @Column({
    type: "enum",
    enum: RoleType,
    default: RoleType.USER,
  })
  role: RoleType;

  @BeforeInsert()
  async forbidUserRoleChangeToAdmin() {
    if (this.role === RoleType.ADMIN) {
      this.role = RoleType.USER;
    }
  }

  /***
   * Auto-generated entries start here:
   * ***/

  // Instead of select: false, use class-transformer's @Exclude()
  // @Column({ select: false })
  @Exclude()
  @Column({ nullable: true }) // For Google account
  @Length(5)
  password: string;

  @Exclude()
  @Column({ name: "reset_password_token", unique: true, nullable: true })
  resetPasswordToken: string;

  @Exclude()
  @Column({
    type: "timestamp",
    name: "reset_password_expire",
    nullable: true,
  })
  resetPasswordExpire: Date;

  @Exclude()
  @Column({ name: "confirm_email_token", unique: true, nullable: true })
  confirmEmailToken: string;

  @Exclude()
  @Column({ name: "is_email_confirmed", default: false })
  @IsBoolean()
  isEmailConfirmed: boolean;

  @CreateDateColumn({ name: "created_at" })
  createdAt: Date;
}
