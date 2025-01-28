// Import the `useState` hook to manage the input field's state.
import { useState } from "react";

// Define the `MessageInput` component as a functional React component with props.
// Props:
// - `onSubmit`: A callback function triggered when the form is submitted.
// - `disabled`: An optional boolean to enable/disable the input field and submission button.

type MessageInputProps = {
    onSubmit: (message: string) => void;
    disabled?: boolean;
}

const MessageInput: React.FC<MessageInputProps> = ({ onSubmit, disabled = false }) => {
  // State to store the current value of the input field.
  const [input, setInput] = useState("");

  // Event handler to update the `input` state as the user types.
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInput(e.target.value);
  };

  // Event handler to handle form submission.
  // Prevents the default browser behavior, invokes the `onSubmit` callback with the input value,
  // and clears the input field.
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    onSubmit(input);
    setInput("");
  };

  return (
    // Form element for submitting a new message.
    // Calls `handleSubmit` on form submission.
    <form
      onSubmit={handleSubmit}
      className="flex items-center justify-between gap-4"
    >
      {/* Input field for entering the message. */}
      <input
        type="text" // Input type is text.
        value={input} // Bind the input field's value to the `input` state.
        onChange={handleChange} // Update the `input` state on change.
        disabled={disabled} // Disable the field if `disabled` is true.
        placeholder={
          disabled ? "This input has been disabled." : "Your message here"
        } // Show a contextual placeholder based on the `disabled` prop.
        className="form-input" // Add styling to the input field.
      />

      {/* Submit button to send the message. */}
      <button type="submit" className="btn primary" disabled={disabled}>
        {/* SVG icon for an upward arrow, symbolizing submission. */}
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 20 20"
          fill="currentColor"
          className="icon"
        >
          <path
            fillRule="evenodd"
            d="M10 17a.75.75 0 0 1-.75-.75V5.612L5.29 9.77a.75.75 0 0 1-1.08-1.04l5.25-5.5a.75.75 0 0 1 1.08 0l5.25 5.5a.75.75 0 1 1-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0 1 10 17Z"
            clipRule="evenodd"
          />
        </svg>
      </button>
    </form>
  );
};

// Export the `MessageInput` component for use in other parts of the application.
export default MessageInput;