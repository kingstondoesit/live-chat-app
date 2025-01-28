// Import required types and components.
// `InboundMessage` is a type from Ably that represents a message received from a channel.
// `Image` is imported from Next.js for optimized image handling.
import { InboundMessage } from "ably";
import Image from "next/image";


// Define the `MessageItem` component as a functional React component with props.
// Props:
// - `message`: An object representing the message, including data and metadata.
// - `onDelete`: A callback function to handle message deletion, identified by a timeserial.
// - `fromUser`: A boolean indicating whether the message is sent by the current user.
type MessageItemProps = {
    message: InboundMessage;
    onDelete: (timeserial: string) => void;
    fromUser: boolean;
  }

const MessageItem: React.FC<MessageItemProps> = ({ message, onDelete, fromUser }) => {
  // Log the sender of the message and whether it's from the current user (for debugging).
  console.log({ fromUser, user: message.clientId });
  return (
    // The outermost container adjusts its layout based on the sender.
    // If the message is from the current user, it uses `flex-row-reverse` for alignment.
    <div
      className={`group relative flex w-fit items-start gap-2 rounded-3xl bg-gray-50 p-2 dark:bg-gray-800 ${
        fromUser ? "flex-row-reverse" : "!flex-row"
      }`}
    >
      {/* Display the avatar for the sender. */}
      <figure className="shrink-0 p-1">
        <Image
          src={message.data.avatarUrl} // URL for the avatar image.
          alt="avatar" // Alternative text for accessibility.
          className="h-8 w-8 rounded-full" // Styling for a circular avatar.
          width={32}
          height={32}
        />
      </figure>
      {/* Display the message content. */}
      <div
        className={`flex flex-col ${
          fromUser ? "pl-2 text-right" : "pr-2 text-left"
        }`}
      >
        {/* The message text, styled for readability. */}
        <span className={`font-medium text-gray-900 dark:text-white`}>
          {message.data.text}
        </span>
        {/* The message timestamp, formatted as a localized time string. */}
        <span
          className={`truncate text-[0.625rem] text-gray-500 dark:text-gray-400`}
        >
          {new Date(message.timestamp).toLocaleTimeString()}
        </span>
      </div>
      {/* If the message is from the current user, show a delete button. */}
      {fromUser && (
        <button
          onClick={() => onDelete(message.id as string)} // Call the `onDelete` function with the message ID.
          className="btn invisible absolute z-[5] flex group-hover:visible"
        >
          {/* Icon for the delete button, rendered as an SVG. */}
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
            className="icon"
          >
            <path
              fillRule="evenodd"
              d="M8.75 1A2.75 2.75 0 0 0 6 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 1 0 .23 1.482l.149-.022.841 10.518A2.75 2.75 0 0 0 7.596 19h4.807a2.75 2.75 0 0 0 2.742-2.53l.841-10.52.149.023a.75.75 0 0 0 .23-1.482A41.03 41.03 0 0 0 14 4.193V3.75A2.75 2.75 0 0 0 11.25 1h-2.5ZM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4ZM8.58 7.72a.75.75 0 0 0-1.5.06l.3 7.5a.75.75 0 1 0 1.5-.06l-.3-7.5Zm4.34.06a.75.75 0 1 0-1.5-.06l-.3 7.5a.75.75 0 1 0 1.5.06l.3-7.5Z"
              clipRule="evenodd"
            />
          </svg>
        </button>
      )}
    </div>
  );
};

// Export the `MessageItem` component for use in other parts of the application.
export default MessageItem;