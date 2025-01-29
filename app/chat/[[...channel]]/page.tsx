"use client"; 

import Chat from "@/app/chat"; // Chat component to handle chat messages and functionality.
import ChatChannelList from "@/app/chat/ChannelList"; // Sidebar with a list of available chat channels.
import { Realtime } from "ably"; // Ably Realtime client for managing connections and messaging.
import { AblyProvider, ChannelProvider } from "ably/react"; // Providers for using Ably hooks in React components.
import { SessionProvider } from "next-auth/react"; // Provider for managing authentication state.
import { use } from "react"; // Hook to handle async data like the `params` object.

// The Page component defines the layout and functionality for the chat application.
const Page = ({ params }: { params: Promise<{ channel: string[] }> }) => {

  // 👉 Create an Ably Realtime client instance
  //    - `authUrl`: URL for authorizing the connection using a token-based authentication strategy.
  //    - `autoConnect`: Ensures the client connects only when the app runs in the browser.
  const client = new Realtime({
    authUrl: "/api/ably", // Authorization endpoint to secure the Ably connection.
    autoConnect: typeof window !== "undefined", // Only auto-connect in the browser.
  });

  // Extract the `channel` parameter from the dynamic route.
  // The `params` object is an async promise containing the route parameters.
  const { channel } = use(params);

  // Format the channel name to match the expected format in the application.
  // For example, if `channel` is "general", the `channelName` becomes "chat:general".
  const channelName = `chat:${channel}`;
  
  return (
    // 👉 Wrap the entire application in providers to manage state and context.
    // `SessionProvider`: Manages the user's authentication session globally.
    <SessionProvider>
      {/* `AblyProvider`: Provides Ably context to child components for accessing the Realtime client. */}
      <AblyProvider client={client}>
        {/* `ChannelProvider`: Supplies the current channel context to components like Chat. */}
        <ChannelProvider channelName={channelName}>
          {/* Main chat application layout */}
          <section className="site-section !p-0">
            <div className="wrapper grid h-[calc(100vh-4.25rem)] grid-cols-4 !p-0">
              {/* Sidebar: Displays the list of available chat channels */}
              <div className="h-full max-h-full rounded-xl bg-gray-50 p-5 dark:bg-gray-800">
                <ChatChannelList />
              </div>
              {/* Main Chat Area: Center column for chat messages and input */}
              <div className="col-span-2 flex h-full flex-col overflow-hidden">
                {/* Pass the current channel name to the Chat component */}
                <Chat channelName={channelName} />
              </div>
              {/* Right Sidebar: Reserved for additional features like a user list */}
              <div className="col-span-1 flex h-full flex-col">
                {/* TODO: Implement a user list or additional features in the right sidebar */}
              </div>
            </div>
          </section>
        </ChannelProvider>
      </AblyProvider>
    </SessionProvider>
  );
};

export default Page; // Export the Page component as the default export.