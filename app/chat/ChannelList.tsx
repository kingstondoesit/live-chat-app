// Imports necessary modules for navigation and routing
import Link from "next/link";
import { usePathname } from "next/navigation";

// Defines the available chat channels with their IDs and display names
export const channels = [
  { id: "general", name: "General" },
  { id: "random", name: "Random" },
  { id: "mod", name: "Moderators" },
];

const ChatChannelList = () => {
  // Retrieves the current path to determine the active channel
  const pathname = usePathname();

  return (
    <ul className="flex flex-col">
      {channels.map((channel) => (
        <li key={channel.id}>
          {/* Creates a link for each channel */}
          <Link
            href={`/chat/${channel.id}`}
            className={`${
              pathname === `/chat/${channel.id}` ? "font-bold" : "" // Highlights the active channel
            }`}
          >
            <span className="truncate">{channel.name}</span>{" "}
            {/* Displays the channel name */}
          </Link>
        </li>
      ))}
    </ul>
  );
};

export default ChatChannelList; // Exports the component for use in other parts of the application