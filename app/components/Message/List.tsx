// Import required types and components.
// `InboundMessage` is a type from Ably that represents a message object.
// `MessageItem` is a child component that renders individual messages.
// `useSession` is a hook from NextAuth used to access the authenticated user's session data.
import { InboundMessage } from "ably";
import MessageItem from "@/app/components/Message/Item";
import { useSession } from "next-auth/react";

// Define the `MessageList` component as a functional React component with props.
// Props:
// - `messages`: An array of `InboundMessage` objects representing chat messages.
// - `onDelete`: A callback function to handle message deletion, identified by a timeserial.

type MessageListProps = {
  messages: InboundMessage[];
  onDelete: (timeserial: string) => void;
};

const MessageList: React.FC<MessageListProps> = ({ messages, onDelete }) => {
  // Retrieve the current session data to identify the logged-in user.
  const session = useSession();

  return (
    // Render a list of messages as a vertical column.
    // The container ensures messages are aligned at the bottom of the view and spaced apart.
    <ul className="flex h-full flex-col justify-end gap-2">
      {/* Map over the `messages` array to render each message. */}
      {messages.map((message) => {
        // Determine if the message is from the logged-in user by comparing their email
        // with the message's `clientId` in a case-insensitive manner.
        const fromUser =
          session?.data?.user?.email?.trim().toLowerCase() ===
          message.clientId?.trim().toLowerCase();

        return (
          // Each message is wrapped in a `li` element for semantic HTML.
          // If the message is from the user, apply additional styles (`self-end`) for alignment.
          <li
            className={`flex flex-row items-start gap-2 ${fromUser ? "self-end" : ""}`}
            key={message.id} // Use the message ID as the unique key for React's reconciliation.
          >
            {/* Render the `MessageItem` component for each message.
                Pass the `message`, the `onDelete` callback, and the `fromUser` flag as props. */}
            <MessageItem
              message={message}
              onDelete={onDelete}
              fromUser={fromUser}
            />
          </li>
        );
      })}
    </ul>
  );
};

// Export the `MessageList` component for use in other parts of the application.
export default MessageList;