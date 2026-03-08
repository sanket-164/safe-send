"use client";

import { Separator } from "@radix-ui/react-separator";
import { Card, CardContent } from "../ui/card";
import { Userprofile } from "./UserProfile";
import { PasswordChange } from "./PasswordChange";

export interface UserDataProps {
  id: string;
  name: string;
  email: string;
  public_key: string | null;
}

export const Profile = ({ userData }: { userData: UserDataProps }) => {
  return (
    <Card>
      <CardContent>
        <Userprofile userData={userData} />
        <Separator />
        <PasswordChange />
      </CardContent>
    </Card>
  );
};
