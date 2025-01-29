
import { useEffect, useState } from "react";
import { useChannel } from "ably/react";
import { InboundMessage } from "ably";
import { useSession } from "next-auth/react";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import MessageList from "@/app/components/Message/List";
import MessageInput from "@/app/components/Message/Input";

// The Chat component handles a chat channel, listens to new messages,
// publishes new messages, and displays them in a scrollable area.
const Chat: React.FC<{ channelName: string }> = ({ channelName }) => {
  const session = useSession(); // Access session data for user info
  const [messages, setMessages] = useState<InboundMessage[]>([]); // Local state to store messages
  
  // useChannel hook from Ably listens for messages on the provided channel
  // and updates the messages list based on the received action.
  const { channel, publish } = useChannel(channelName, (message) => {
    if (message.name === "ADD" || message.name === "PROMOTE")
      setMessages((messages) => [...messages, message as InboundMessage]);
    if (message.name === "DELETE")
      setMessages((messages) =>
        messages.filter((m) => {
          // Remove the message if it matches the one being deleted.
          const matchingMessage = m.id === message.extras?.ref?.id;
          const isOwnMessage = m.clientId === message.clientId;
          return !(matchingMessage && isOwnMessage);
        }),
      );
    if (message.name === "PROMOTE" || message.name === "DEMOTE") {
      setMessages((messages) => [...messages, message as InboundMessage]);
    }
  });

  // Function to publish a new message to the channel via Ably
  const publishMessage = (text: string) => {
    publish({
      name: "ADD",
      data: {
        text, // Message content
        avatarUrl: session?.data?.user?.image as string, // User avatar URL
      },
    });
  };

  // Function to handle deleting a message by publishing a delete event
  const handleDelete = (id: string) => {
    publish({
      name: "DELETE",
      extras: {
        ref: { id },
      },
    });
  };
  
  // Fetching message history from the channel when the component mounts
  useEffect(() => {
    let ignore = false; // To prevent state updates after unmount
    const fetchHist = async () => {
      console.log("fetching history");
      const history = await channel.history({
        limit: 100, // Limit to the last 100 messages
        direction: "forwards", // Fetch from earliest to latest
      });
      if (!ignore)
        history.items.forEach((item) => {
          if (item.name === "ADD")
            setMessages((messages) => [...messages, item as InboundMessage]);
          if (item.name === "DELETE")
            setMessages((messages) =>
              messages.filter((m) => {
                const matchingMessage =
                  m.extras?.timeserial === item.extras?.ref?.timeserial;
                const isOwnMessage = m.clientId === item.clientId;
                return !(matchingMessage && isOwnMessage);
              }),
            );
        });
    };
    fetchHist();
    return () => {
      ignore = true; // Cleanup on unmount to avoid memory leaks
    };
  }, [channel]); // Effect runs when the channel changes
  return (
    <>
      {/* Scrollable area for message list */}
      <ScrollArea.Root className="h-full w-full overflow-hidden rounded bg-white dark:bg-gray-900">
        <ScrollArea.Viewport className="flex size-full flex-col justify-end rounded p-4">
          {/* List of messages */}
          <MessageList messages={messages} onDelete={handleDelete} />
        </ScrollArea.Viewport>
        {/* Vertical scrollbar for the message area */}
        <ScrollArea.Scrollbar
          className="flex touch-none select-none p-0.5 transition-colors ease-out data-[orientation=horizontal]:h-2.5 data-[orientation=vertical]:w-2.5 data-[orientation=horizontal]:flex-col"
          orientation="vertical"
        >
          <ScrollArea.Thumb className="relative flex-1 rounded-[10px] bg-gray-200 before:absolute before:left-1/2 before:top-1/2 before:size-full before:min-h-11 before:min-w-11 before:-translate-x-1/2 before:-translate-y-1/2" />
        </ScrollArea.Scrollbar>
        {/* Horizontal scrollbar for the message area */}
        <ScrollArea.Scrollbar
          className="flex touch-none select-none p-0.5 transition-colors ease-out data-[orientation=horizontal]:h-2.5 data-[orientation=vertical]:w-2.5 data-[orientation=horizontal]:flex-col"
          orientation="horizontal"
        >
          <ScrollArea.Thumb className="bg-mauve10 relative flex-1 rounded-[10px] before:absolute before:left-1/2 before:top-1/2 before:size-full before:min-h-[44px] before:min-w-[44px] before:-translate-x-1/2 before:-translate-y-1/2" />
        </ScrollArea.Scrollbar>
        {/* Scroll area corner */}
        <ScrollArea.Corner className="" />
      </ScrollArea.Root>
      {/* Message input field at the bottom */}
      <div className="mt-auto p-5">
        <MessageInput onSubmit={publishMessage} />
      </div>
    </>
  );
};
export default Chat;