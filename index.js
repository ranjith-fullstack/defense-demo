const express = require("express");
const dgram = require("dgram");
const http = require("http");
const { Server } = require("socket.io");


const app = express();
const server = http.createServer(app);
const io = new Server(server);

const HTTP_PORT = process.env.PORT || 3000;
let LOCAL_UDP_PORT = null;
let REMOTE_UDP_PORT = null;
let MICROCONTROLLER_IP = null;

let udpSocket = null;
let clientCount = 0;

// Serve static files
app.use(express.static("public"));

// Serve the main HTML file
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// Serve the login HTML file
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

// Serve the homepage HTML file
app.get("/home", (req, res) => {
  res.sendFile(__dirname + "/home.html");
});

function handleMessage(hexArray) {
  if (!Array.isArray(hexArray)) {
    throw new Error(
      "Invalid input: Expected an array of hex values (bytes). Each value should be between 0x00 and 0xFF."
    );
  }

  if (hexArray.length < 4) {
    throw new Error(
      "Invalid message: Must be at least 4 bytes (size + operation code)."
    );
  }

  // Extract message size (first two bytes, unsigned integer)
  let messageSize = (hexArray[0] << 8) | hexArray[1];

  // Extract operation code (next two bytes, unsigned integer)
  let operationCode = (hexArray[2] << 8) | hexArray[3];
  let data;
  

  // Process message based on operation code
  let result;
  switch (operationCode) {
    case 0x0001:
      // Boot up message ACK
      console.log("Boot up ACK received. Navigating to login page...");
      io.emit("navigateToLogin");
      result = "Boot up ACK received";
      break;
    case 0x0002:
      console.log("Login ACK received.");
      // Extract data (remaining bytes)
      data = hexArray.slice(4);
      // Extract loginack from the last byte of the message (hexArray[6])
      let loginack = data[data.length - 1]; // Last byte of the data array
      if (loginack === 0x00) {
        console.log("Login failed: Incorrect password.");
        io.emit("showError", "Incorrect password"); // Emit an event to show an error message
        result = "Login failed: Incorrect password";
      } else if (loginack === 0x01) {
        // Success case: Navigate to the homepage
        console.log("Login successful. Navigating to homepage...");
        io.emit("navigateToHomepage"); // Emit an event to navigate to the homepage
        result = "Login successful";
      } else {
        // Handle unexpected values
        console.warn("Unknown loginack value:", loginack);
        result = "Unknown loginack value";
      }
      break;
    case 0x0003:
      // Extract data (remaining bytes)
      data = hexArray.slice(4);
      console.log("Password change response received.");
      const passwordAck = data[data.length - 1]; // Last byte of the data array
      if (passwordAck === 0x01) {
        // Success case
        console.log("Password change successful.");
        io.emit("passwordChangeSuccess");
      } else if (passwordAck === 0x00) {
        // Failure case
        console.log("Password change failed.");
        io.emit(
          "passwordChangeError",
          "Password change failed. Incorrect old password."
        );
      } else {
        // Handle unexpected values
        console.warn("Unknown passwordAck value:", passwordAck);
        io.emit(
          "passwordChangeError",
          "Unknown error occurred during password change."
        );
      }
      break;
    case 0x0006:
      // Extract data (remaining bytes)
      data = hexArray.slice(4);
      console.log("Network settings response received.");
      const networkAck = data[data.length - 1]; // Last byte of the data array
      if (networkAck === 0x01) {
        // Success case
        console.log("Network settings saved successfully.");
        io.emit("networkSettingsSuccess");
      } else if (networkAck === 0x00) {
        // Failure case
        console.log("Network settings save failed.");
        io.emit("networkSettingsError", "Network settings save failed.");
      } else {
        // Handle unexpected values
        console.warn("Unknown networkAck value:", networkAck);
        io.emit(
          "networkSettingsError",
          "Unknown error occurred during network settings save."
        );
      }
      break;
    case 0x0005:
      console.log("Logout response received.");
      // Extract data (remaining bytes)
      data = hexArray.slice(4);
      const logoutAck = data[data.length - 1]; // Last byte of the data array
      if (logoutAck === 0x01) {
        // Success case
        console.log("Logout successful.");
        io.emit("logoutSuccess");
      } else if (logoutAck === 0x00) {
        // Failure case
        console.log("Logout failed.");
        io.emit("logoutError", "Logout failed.");
      } else {
        // Handle unexpected values
        console.warn("Unknown logoutAck value:", logoutAck);
        io.emit("logoutError", "Unknown error occurred during logout.");
      }
      break;
      case 0x0008: // Auto/Manual toggle response
  console.log("Auto/Manual toggle response received.");
  const messageLength = (hexArray[0] << 8) | hexArray[1]; // First 2 bytes: message length
  const autoManualAck = hexArray[6]; // 7th byte (0x01 for auto, 0x00 for manual)
  const sequenceSize = hexArray[7]; // 8th byte (number of sequences)
  const lastByte = hexArray[hexArray.length - 1]; // Last byte of the message

  if (messageLength === 0x0007) {
    // Manual mode acknowledgment (00070008000100 or 00070008000101)
    if (lastByte === 0x00) {
      // Navigate to Home Page (Manual Mode)
      console.log("Manual mode acknowledgment received. Navigating to Home Page.");
      io.emit("navigateToHomepage");
    } else if (lastByte === 0x01) {
      // Stay in Auto Page
      console.log("Manual mode acknowledgment received. Staying in Auto Page.");
      // No action needed, stay in Auto Page
    } else {
      // Handle unexpected values
      console.warn("Unknown last byte value:", lastByte);
      io.emit("autoManualToggleError", "Unknown last byte value in acknowledgment.");
    }
  } else if (autoManualAck === 0x01) {
    // Auto mode
    console.log("Auto mode acknowledgment received.");
    if (sequenceSize === 0x00) {
      // No sequence, navigate to auto page without buttons
      io.emit("autoManualToggleSuccess", { mode: "auto", sequences: [] });
    } else {
      // Parse sequence data
      const sequences = [];
      let offset = 8; // Start of sequence data
      for (let i = 0; i < sequenceSize; i++) {
        const sequenceNumber = hexArray[offset];
        const relayNumber = hexArray[offset + 1];
        const preOpDelay = (hexArray[offset + 2] << 8) | hexArray[offset + 3];
        const operation = hexArray[offset + 4];
        const postOpDelay = (hexArray[offset + 5] << 8) | hexArray[offset + 6];
        sequences.push({
          sequenceNumber,
          relayNumber,
          preOpDelay,
          operation,
          postOpDelay,
        });
        offset += 7; // Move to the next sequence
      }
      // Navigate to auto page with sequences
      io.emit("autoManualToggleSuccess", { mode: "auto", sequences });
    }
  } else if (autoManualAck === 0x00) {
    // Manual mode, navigate to homepage
    console.log("Manual mode acknowledgment received.");
    io.emit("navigateToHomepage");
  } else {
    // Handle unexpected values
    console.warn("Unknown autoManualAck value:", autoManualAck);
    io.emit("autoManualToggleError", "Unknown error occurred during Auto/Manual toggle.");
  }
  break; 
  
  
  case 0x0004:
        sequenceData = hexArray.slice(7);
        console.log("Sequence response received.");
        const sequenceAck = hexArray[5]; // Last byte of the data array
        console.log("hexArray be:", hexArray);
         // Check if this is a new sequence or an edit sequence
        const isNewSequence = hexArray[5] === 0x01; // Flag to distinguish new vs edit
        if (sequenceAck === 0x01) {
          // Success case
          console.log("Sequence saved successfully.");
          if (isNewSequence) {
            io.emit("editSequenceSaveSuccess", sequenceData);
            io.emit("uniqueSequenceSaveSuccess", sequenceData);
          } 
        } else if (sequenceAck === 0x00) {
          // Failure case
          console.log("Sequence save failed.");
          if (isNewSequence) {
            // Emit error for new sequence
            io.emit("uniqueSequenceSaveError", "Sequence save failed.");
          } else {
            // Emit error for edit sequence
            io.emit("editSequenceSaveError", "Sequence save failed.");
          }
        } else {
          // Handle unexpected values
          console.warn("Unknown sequenceAck value:", sequenceAck);
          if (isNewSequence) {
            io.emit(
              "uniqueSequenceSaveError",
              "Unknown error occurred during sequence save.", sequenceAck
            );
          } else {
            io.emit(
              "editSequenceSaveError",
              "Unknown error occurred during sequence save.", sequenceAck
            );
          }
        }
        break;
      
        case 0x0007: // Start/Stop acknowledgment
      console.log("Start/Stop ACK received.");
      const startStopAck = hexArray[6]; // Last byte of the data array
      if (startStopAck === 0x00) {
        // Stop acknowledgment
        console.log("Stop acknowledgment received.");
        io.emit("startStopAck", false); // Emit event to update button to "Start"
      } else if (startStopAck === 0x01) {
        // Start acknowledgment
        console.log("Start acknowledgment received.");
        io.emit("startStopAck", true); // Emit event to update button to "Stop"
      } else {
        // Handle unexpected values
        console.warn("Unknown startStopAck value:", startStopAck);
      }
      break;
      case 0x000A: // Restart acknowledgment
      console.log("Restart ACK received.");
      const restartAck = hexArray[5]; // Last byte of the data array
      console.log("restart",restartAck)
      if (restartAck === 0x01) {
        // Restart acknowledgment
        console.log("Restart acknowledgment received.");
        io.emit("restartAck"); // Emit event to confirm restart
      } else {
        // Handle unexpected values
        console.warn("Unknown restartAck value:", restartAck);
      }
      break;
      case 0x000B: // Delete sequence acknowledgment
  console.log("Delete sequence ACK received.");
  const deleteAck = hexArray[5]; // Last byte of the data array
  if (deleteAck === 0x01) {
    // Success case: All sequences have been deleted
    console.log("All sequences deleted successfully.");
    io.emit("deleteSequenceAck"); // Emit event to confirm deletion
  } else {
    // Handle unexpected values
    console.warn("Unknown deleteAck value:", deleteAck);
  }
  break;
  case 0x000C: // New data format
      console.log("New data format received.");
      if (hexArray.length !== messageSize) {
        console.error("Data length mismatch.");
        return "Data length mismatch.";
      }

      // Extract data (remaining bytes)
      data = hexArray.slice(4);

      // Parse the data
      const v1 = (data[0] << 8) | data[1];
      const v2 = (data[2] << 8) | data[3];
      const v3 = (data[4] << 8) | data[5];
      const v4 = (data[6] << 8) | data[7];
      const i1 = (data[8] << 8) | data[9];
      const i2 = (data[10] << 8) | data[11];
      const i3 = (data[12] << 8) | data[13];
      const frequency = data[14];

      // Emit the parsed data to the frontend
      io.emit("newData", {
        v1,
        v2,
        v3,
        v4,
        i1,
        i2,
        i3,
        frequency
      });

      result = "New data format processed successfully.";
      break;
      case 0x0009:
    console.log("Relay operation ACK received.");
    const relayStatus = hexArray.slice(6); // Extract relay statuses
    console.log("relay",relayStatus)
    io.emit("relayStatusUpdate", relayStatus); // Emit relay statuses to the frontend
    result = "Relay operation ACK received";
    break;
    default:
      result = `Unknown operation code: 0x${operationCode
        .toString(16)
        .padStart(4, "0")}`;
      console.warn(result); // Log unknown operation codes as warnings
      break;
  }

  return result;
}
// Function to start UDP socket
function startUDPSocket(localPort, remotePort, ipAddress) {
  if (!udpSocket) {
    udpSocket = dgram.createSocket("udp4");

    udpSocket.bind(localPort, () => {
      console.log(`UDP socket bound to local port ${localPort}`);
    });

    udpSocket.on("message", (msg, rinfo) => {
      console.log(
        `Received from ${rinfo.address}:${rinfo.port}: ${msg.toString()}`
      );

      // Convert ASCII hex to raw byte array
      const asciiString = msg.toString().trim(); // Convert Buffer to string
      const hexArray = [];

      // Convert each pair of characters (hex string) into a byte
      for (let i = 0; i < asciiString.length; i += 2) {
        hexArray.push(parseInt(asciiString.substr(i, 2), 16));
      }

      console.log("Converted Hex Array:", hexArray); // Now this should be [0x00, 0x06, 0x00, 0x01, 0x00, 0x00]

      // Pass the fixed hex array to handleMessage function
      const result = handleMessage(hexArray);

      io.emit(
        "udpMessage",
        `Received from ${rinfo.address}:${rinfo.port} - ${hexArray
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" ")}`
      );
    });

    udpSocket.on("error", (err) => {
      console.error("UDP socket error:", err);
    });

    // Set remote port and IP address
    REMOTE_UDP_PORT = remotePort;
    MICROCONTROLLER_IP = ipAddress;
  }
}

// Function to stop UDP socket
function stopUDPSocket() {
  if (udpSocket) {
    udpSocket.close(() => {
      console.log("UDP socket closed.");
    });
    udpSocket = null;
  }
}

// Function to send UDP message
function sendUdpMessage(message, ip, port) {
  if (!udpSocket) {
    console.error("UDP socket is not initialized.");
    return;
  }

  let buffer;

  // Check if the message is an array of bytes
  if (Array.isArray(message)) {
    // Convert the byte array to a Buffer
    buffer = Buffer.from(message);
  } else if (typeof message === "string") {
    // If the message is a string, convert it to a Buffer
    buffer = Buffer.from(message, "utf-8");
  } else if (message instanceof Buffer) {
    // If the message is already a Buffer, use it directly
    buffer = message;
  } else {
    console.error(
      "Invalid message format. Expected an array, string, or Buffer."
    );
    return;
  }

  // Send the UDP message
  udpSocket.send(buffer, 0, buffer.length, port, ip, (err) => {
    if (err) {
      console.error("UDP send error:", err);
    } else {
      console.log(`UDP message sent to ${ip}:${port}`);
    }
  });
}

// Handle WebSocket connections
io.on("connection", (socket) => {
  clientCount++;
  console.log(`WebSocket Client Connected. Total clients: ${clientCount}`);

  // Listen for UDP port configuration from the client
  socket.on("setUdpConfig", (config) => {
    LOCAL_UDP_PORT = config.localPort;
    REMOTE_UDP_PORT = config.remotePort;
    MICROCONTROLLER_IP = config.ipAddress;

    // Start the UDP socket with the provided configuration
    startUDPSocket(LOCAL_UDP_PORT, REMOTE_UDP_PORT, MICROCONTROLLER_IP);

    // Send a test message to the microcontroller
    let message = [0x00, 0x06, 0x00, 0x01, 0x00, 0x00];

    sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);

    console.log(
      `UDP configuration set: IP=${MICROCONTROLLER_IP}, Remote Port=${REMOTE_UDP_PORT}, Local Port=${LOCAL_UDP_PORT}`
    );
  });

  // Listen for login attempts from the client
  socket.on("loginAttempt", (password) => {
    // Convert each character to a hex number (e.g., "1" → 0x01, "2" → 0x02, etc.)
    let passwordBytes = Buffer.from(password.split("").map(digit => parseInt(digit, 10)));
    // Construct the initial message
    let message = Buffer.from([0x00, 0x0B, 0x00, 0x02, 0x00, 0x00]);
    // Concatenate the message with the password bytes
    let fullMessage = Buffer.concat([message, passwordBytes]);

    // Send via UDP
    sendUdpMessage(fullMessage, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log("Login change request sent to microcontroller:", fullMessage);
});


  socket.on("changePassword", (data) => {
    const { oldPassword, newPassword, confirmPassword } = data;

    // Check if new password and confirm password match
    if (newPassword !== confirmPassword) {
      socket.emit(
        "passwordChangeError",
        "New password and confirm password do not match."
      );
      return;
    }

    // Validate new password length (must be exactly 5 characters)
    if (newPassword.length !== 5) {
      socket.emit(
        "passwordChangeError",
        "New password must be exactly 5 characters long."
      );
      return;
    }

    // Validate old password length (must be exactly 5 characters)
    if (oldPassword.length !== 5) {
      socket.emit(
        "passwordChangeError",
        "Old password must be exactly 5 characters long."
      );
      return;
    }

    // Construct the UDP message for password change
    let message = [0x00, 0x10, 0x00, 0x03, 0x00, 0x00]; // Initial header (Size: 6 bytes, Opcode: 0x0003)

    // Append old password (5 bytes)
    for (let i = 0; i < 5; i++) {
      message.push(oldPassword.charCodeAt(i));
    }

    // Append new password (5 bytes)
    for (let i = 0; i < 5; i++) {
      message.push(newPassword.charCodeAt(i));
    }

    // Send the UDP message to the microcontroller
    sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log("Password change request sent to microcontroller:", message);
  });

  socket.on("saveNetworkSettings", (settings) => {
    const { ipAddress, netMask, defaultGateway, mcuPort } = settings;

    // Convert IP addresses to byte arrays
    const ipAddressBytes = ipAddress.split(".").map(Number);
    const netMaskBytes = netMask.split(".").map(Number);
    const defaultGatewayBytes = defaultGateway.split(".").map(Number);

    // Convert MCU port to 2-byte array (big-endian)
    const mcuPortBytes = [(mcuPort >> 8) & 0xff, mcuPort & 0xff];

    // Construct the message (without console port)
    let message = [0x00, 0x16, 0x00, 0x06, 0x00, 0x00]; // Size: 16 bytes, Opcode: 0x0006
    message = message.concat(
      ipAddressBytes,
      defaultGatewayBytes,
      netMaskBytes,
      mcuPortBytes
    );

    // Send the UDP message to the microcontroller
    sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log("Network settings sent to microcontroller:", message);
  });

  socket.on("logoutAttempt", () => {
    // Construct the UDP message for logout
    let message = [0x00, 0x06, 0x00, 0x05, 0x00, 0x00]; // Initial header (Size: 6 bytes, Opcode: 0x0005)

    // Send the UDP message to the microcontroller
    sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log("Logout request sent to microcontroller:", message);
  });

  socket.on("autoManualToggleAttempt", (currentPage) => {
    let message;

    if (currentPage === "homePage") {
      // Construct the UDP message for navigating to auto page (code: 000600080001)
      message = [0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x01]; // 000600080001
    } else if (currentPage === "autoPage") {
      // Construct the UDP message for navigating to home page (code: 000600080000)
      message = [0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00]; // 000600080000
    } else {
      console.error("Invalid currentPage value:", currentPage);
      return; // Exit if the currentPage is invalid
    }

    // Ensure the message is valid before sending
    if (!Array.isArray(message)) {
      console.error("Invalid message format:", message);
      return;
    }

    // Send the UDP message to the microcontroller
    sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log("Auto/Manual toggle request sent to microcontroller:", message);
  });

  socket.on("uniqueSaveSequence", (sequenceData) => {
    console.log("dtaaaaaa",sequenceData)
    // Construct the UDP message for saving the sequence
    let message = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00]; // Initial header (Size: 4 bytes, Opcode: 0x0004)
    let sequence_data_size = sequenceData.length; // Size of the sequence data
    let total_message_size = sequence_data_size + message.length + 1; // Total message size
    // Update the message length in the header
    message[0] = (total_message_size >> 8) & 0xff; // High byte of message length
    message[1] = total_message_size & 0xff; // Low byte of message length
    message[6] = sequence_data_size / 7; // Size of the sequence data
    console.log (sequence_data_size);
    console.log (sequenceData);
    // Append sequence data to the message
    message = message.concat(sequenceData);
    // Send the UDP message to the microcontroller
    sendUdpMessage(Buffer.from(message), MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log("Sequence data sent to microcontroller:", message);

    // Emit the saved data to the frontend
  });
  socket.on("editSaveSequence", (sequenceData) => {
    console.log("Edit sequence data received:", sequenceData);
  
    // Construct the UDP message for saving the sequence
    let message = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00]; // Initial header (Size: 4 bytes, Opcode: 0x0004)
    let sequence_data_size = sequenceData.length; // Size of the sequence data
    let total_message_size = sequence_data_size + message.length + 1; // Total message size
  
    // Update the message length in the header
    message[0] = (total_message_size >> 8) & 0xff; // High byte of message length
    message[1] = total_message_size & 0xff; // Low byte of message length
    message[6] = sequence_data_size / 7; // Size of the sequence data
  
    // Append sequence data to the message
    message = message.concat(sequenceData);
  
    // Send the UDP message to the microcontroller
    sendUdpMessage(Buffer.from(message), MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log("Edit sequence data sent to microcontroller:", message);
  
    // Emit the saved data to the frontend
  });
  socket.on('startStopSequence', (isStart) => {
    let message;
  
    if (isStart) {
      // Start sequence: 00070007000001
      message = [0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x01];
    } else {
      // Stop sequence: 00070007000000
      message = [0x00, 0x07, 0x00, 0x07, 0x00, 0x00, 0x00];
    }
  
    // Send the UDP message to the microcontroller
    sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log('Start/Stop sequence request sent to microcontroller:', message);
  });
  socket.on('restartSequence', () => {
    // Restart sequence: 0006000A000001
    const message = [0x00, 0x06, 0x00, 0x0A, 0x00, 0x00, 0x01];
  
    // Send the UDP message to the microcontroller
    sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log('Restart sequence request sent to microcontroller:', message);
  });

  socket.on('deleteSequence', () => {
    // Construct the delete sequence message
    const deleteMessage = [0x00, 0x07, 0x00, 0x0B, 0x00, 0x00, 0x01];
  
    // Send the UDP message to the microcontroller
    sendUdpMessage(deleteMessage, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
    console.log('Delete sequence request sent to microcontroller:', deleteMessage);
  });


// Handle relay state change from the frontend
socket.on('relayButtonClick', (data) => {
  console.log("Relay operation data received from frontend:", data); // Debugging line
  const { relayNumber, operation } = data;

  // Construct the message
  const message = [
    0x00, 0x08, // Length of message (8 bytes)
    0x00, 0x09, // Operation code (0x0009)
    0x00, // Reserved byte
    0x00, // Reserved byte
    relayNumber - 1, // Relay number (0 to N-1)
    operation // Operation (0x00 for Off, 0x01 for On)
  ];

  // Send the message to the MCU
  sendUdpMessage(message, MICROCONTROLLER_IP, REMOTE_UDP_PORT);
});


  socket.on("uniqueNavigateToAutoPage", () => {
    socket.emit("uniqueNavigateToAutoPage");
  });
  socket.on('requestSequenceData', () => {
    socket.emit('requestSequenceData');
  });
  socket.on("disconnect", () => {
    clientCount--;
    console.log(
      `WebSocket Client Disconnected. Remaining clients: ${clientCount}`
    );

    if (clientCount === 0) {
      console.log("No more WebSocket clients. Stopping server...");
      stopUDPSocket();
      server.close(() => {
        console.log("HTTP server stopped.");
        process.exit(0);
      });
    }
  });
});

// Start HTTP server
server.listen(HTTP_PORT, () => {
  console.log(`Server running at http://localhost:${HTTP_PORT}`);


});
