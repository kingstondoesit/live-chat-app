// Import the `auth` function to authenticate the user.
// Import `SignJWT` from the `jose` library to create JSON Web Tokens (JWT).
import { auth } from "@/auth";
import { SignJWT } from "jose";
import { NextResponse } from "next/server";

/**
 * Creates an Ably-compatible JSON Web Token (JWT) for Ably authentication with specified capabilities and claims.
 * @param {string} clientId - The unique identifier for the client.
 * @param {string} apiKey - The Ably API key in the format "appId:signingKey".
 * @param {{ isMod: boolean }} claim - An object indicating the user's role (e.g., whether they are a moderator).
 * @param {{ [key: string]: string[] | undefined }} capability - A map of channel permissions for the user.
 * @returns {Promise<string>} A Promise that resolves to the signed JWT string.
 * 
 * @example
 * const token = await createToken(
 *   "user123",
 *   "appId:signingKey",
 *   { isMod: true },
 *   { "channel1": ["publish", "subscribe"] }
 * );
 */
const createToken = (
    clientId: string,
    apiKey: string,
    claim: { isMod: boolean },
    capability: { [key: string]: string[] | undefined },
) => {

    // Extract the app ID and signing key from the provided Ably API key.
    const [appId, signingKey] = apiKey.split(":", 2);
    // Create a text encoder to encode the signing key for the JWT.
    const enc = new TextEncoder();
    // Create the JWT with Ably-specific claims and headers.
    const token = new SignJWT({
        // Specify the user's capabilities for Ably channels.
        "x-ably-capability": JSON.stringify(capability),
        // Associate the token with the client's unique identifier.
        "x-ably-clientId": clientId,
        // Include custom claims (e.g., moderation status).
        "ably.channel.*": JSON.stringify(claim),
    })
        // Set the protected header with the app ID and algorithm used for signing.
        .setProtectedHeader({ kid: appId, alg: "HS256" })
        // Set the issued-at timestamp to the current time.
        .setIssuedAt()
        // Set the expiration time for the token to 24 hours.
        .setExpirationTime("24h")
        // Sign the token using the encoded signing key.
        .sign(enc.encode(signingKey));
    // Return the signed JWT.
    return token;
};

// Function to generate channel permissions (capabilities) based on the user's role.
// Parameters:
// - `claim`: An object indicating the user's role (e.g., whether they are a moderator).
// Returns:
// - An object specifying the user's capabilities for different channels.
const generateCapability = (claim: { isMod: boolean }) => {
    if (claim.isMod) {
        // Moderators have full access to all channels.
        return { "*": ["*"] };
    } else {
        // Regular users have specific permissions for certain channels.
        return {
            "chat:general": ["subscribe", "publish", "presence", "history"],
            "chat:random": ["subscribe", "publish", "presence", "history"],
            "chat:announcements": ["subscribe", "presence", "history"],
        };
    }
};

// Handler for the GET request to this API route.
// Generates an Ably token for the authenticated user and returns it.
export const GET = async () => {
    try {
        // Authenticate the user and get their session.
        const session = await auth();
        const user = session?.user;
        // Define the user's role as non-moderator by default.
        const userClaim = {
            isMod: false, // Define the user's role based on session information.  
            // isMod: user?.role === 'moderator', // Check if user role is 'moderator'  
        };
        // Generate the user's channel permissions based on their role.
        const userCapability = generateCapability(userClaim);
        // If the user is authenticated, create a signed token for them.
        const token =
            user?.email &&
            (await createToken(
                user?.email, // Use the user's email as the client ID.
                process.env.ABLY_SECRET_KEY as string, // Use the Ably secret key from environment variables.
                userClaim, // Pass the user's role.
                userCapability, // Pass the generated channel permissions.
            ));
        // If token generation was successful, return it.
        if (token) {
            return NextResponse.json({ success: true, token: token });
        }

        // If token generation failed, handle the error.
        return NextResponse.json({ success: false, error: 'Token generation failed' }, { status: 500 });

    } catch (error) {
        // Handle any errors that may occur during the execution.
        console.error('Error in Token GET handler:', error);
        return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
    }
};