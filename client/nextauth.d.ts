import { DefaultSession } from "next-auth";

export type ExtendUser = DefaultSession["user"] & {
    accessToken: string;
}

declare module "next-auth" {
    interface User {
        token: string;
    }


    interface Session {
        user: ExtendUser;
    }
}