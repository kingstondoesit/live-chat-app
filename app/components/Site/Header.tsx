// Importing necessary modules and functions:
// - `auth`, `signIn`, `signOut`: Authentication-related functions from the custom `auth` module.
// - `Image` from `next/image`: For optimized image rendering.
// - `Link` from `next/link`: For client-side navigation in Next.js.
import { auth, signIn, signOut } from "@/auth";
import Image from "next/image";
import Link from "next/link";
// Define the `SiteHeader` component as an async function since it fetches session data.
const SiteHeader = async () => {
  // Fetch the current user's session using the `auth` function.
  const session = await auth();
  return (
    // Define the header with styling for sticky positioning, background, and padding.
    <header className="noscroll sticky top-0 z-10 overflow-auto bg-white dark:bg-gray-900 px-4 py-4 sm:px-6 lg:px-8">
      <div className="wrapper mx-auto flex max-w-5xl items-center justify-between gap-4">
        {/* Navigation link to the homepage. */}
        <Link href="/">
          <figure className="flex items-center">
            <span className="truncate text-xl font-bold tracking-tight text-gray-900 dark:text-white">
              Live Chat
            </span>
          </figure>
        </Link>
        {/* Navigation menu */}
        <nav className="site-nav flex">
          <ul className="flex items-center gap-2">
            {/* If the user is signed in, show their profile picture, name, and a sign-out button. */}
            {session?.user ? (
              <>
                <li>
                  <button className="btn">
                    {/* Display the user's avatar using the `Image` component. */}
                    <Image
                      src={session?.user.image as string} // User's profile image URL.
                      alt="session?.user avatar" // Alternative text for accessibility.
                      width={32}
                      height={32}
                      className="icon rounded-full"
                    />
                    <span className="truncate">{session?.user.name}</span>{" "}
                    {/* User's name. */}
                  </button>
                </li>
                <li>
                  <button
                    onClick={async () => {
                      "use server"; // Mark this function for server execution.
                      await signOut(); // Sign the user out when clicked.
                    }}
                    className="btn truncate"
                  >
                    Sign out
                  </button>
                </li>
              </>
            ) : (
              // If no user is signed in, show a sign-in button.
              <li>
                <form
                  action={async () => {
                    "use server"; // Mark this function for server execution.
                    await signIn(); // Sign the user in when submitted.
                  }}
                >
                  <button type="submit" className="btn">
                    Sign in
                  </button>
                </form>
              </li>
            )}
          </ul>
        </nav>
      </div>
    </header>
  );
};

// Export the `SiteHeader` component as the default export of this module.
export default SiteHeader;