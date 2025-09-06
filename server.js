// server.js
console.log("Server file version: 2");
const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 5003;
const DATA_FILE = path.join(__dirname, "data.json");
const SECRET = process.env.JWT_SECRET || "supersecretkey"; // set env var in production

const commonPrefixes = ["+93", "+355", "+213", "+376", "+244", "+54", "+61", "+43", "+880", "+375", "+32", "+975", "+591", "+387", "+55", "+359", "+226", "+855", "+237", "+1", "+236", "+235", "+56", "+86", "+57", "+243", "+242", "+506", "+385", "+53", "+357", "+420", "+45", "+253", "+1", "+593", "+20", "+503", "+372", "+251", "+358", "+33", "+241", "+220", "+995", "+49", "+233", "+30", "+502", "+224", "+504", "+852", "+36", "+354", "+91", "+62", "+98", "+964", "+353", "+972", "+39", "+225", "+81", "+962", "+7", "+254", "+965", "+856", "+371", "+961", "+231", "+218", "+370", "+352", "+261", "+60", "+223", "+356", "+222", "+52", "+373", "+377", "+976", "+382", "+212", "+258", "+95", "+977", "+31", "+64", "+505", "+227", "+234", "+850", "+389", "+47", "+968", "+92", "+507", "+595", "+51", "+63", "+48", "+351", "+974", "+40", "+7", "+250", "+966", "+221", "+381", "+65", "+421", "+386", "+252", "+27", "+82", "+34", "+94", "+249", "+46", "+41", "+963", "+255", "+66", "+228", "+216", "+90", "+256", "+380", "+971", "+44", "+1", "+598", "+998", "+58", "+84", "+967", "+260", "+263"];

app.use(cors());
app.use(express.json());

// === NEW: SEO constants ===
const BASE_URL = "https://readraa.com";
const urls = ["/", "/about", "/contact"]; // add more public paths as your site grows

// === NEW: Sitemap route ===
app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  const now = new Date().toISOString();

  const urlSet = urls.map(path => `
    <url>
      <loc>${BASE_URL}${path}</loc>
      <lastmod>${now}</lastmod>
      <changefreq>weekly</changefreq>
      <priority>${path === "/" ? "1.0" : "0.8"}</priority>
    </url>`).join("");

  res.send(`<?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    ${urlSet}
  </urlset>`);
});

// === NEW: Robots.txt route ===
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send(`User-agent: *
Allow: /

Sitemap: ${BASE_URL}/sitemap.xml
`);
});


// helpers
function readData() {
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], pdfs: [], stories: [], drafts: [], otps: [] }, null, 2)); // Added otps
  }
  const data = JSON.parse(fs.readFileSync(DATA_FILE));
  if (!data.stories) data.stories = [];
  if (!data.drafts) data.drafts = [];
  if (!data.otps) data.otps = []; // Added otps initialization
  return data;
}
function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// auth middleware
function auth(req, res, next) {
  const token = req.headers["authorization"];
  console.log("Auth middleware: Token received:", token ? "Yes" : "No");
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      console.error("Auth middleware: JWT verification error:", err);
      return res.status(403).json({ message: "Invalid token" });
    }
    req.userId = decoded.id;
    req.isAdmin = decoded.isAdmin; // Attach isAdmin from the token
    console.log("Auth middleware: Token valid, userId:", req.userId, "isAdmin:", req.isAdmin);
    next();
  });
}

// admin auth middleware
function adminAuth(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    if (!decoded.isAdmin) return res.status(403).json({ message: "Admin access required" });
    req.userId = decoded.id;
    next();
  });
}

// authorize story action middleware
async function authorizeStoryAction(req, res, next) {
  const storyId = parseInt(req.params.id, 10);
  const data = readData();
  const story = data.stories.find(s => s.id === storyId);

  if (!story) {
    return res.status(404).json({ message: "Story not found" });
  }

  // Check if user is the story owner or an admin
  const user = data.users.find(u => u.id === req.userId);
  const isAdmin = user && user.email === "readraaofficial@gmail.com"; // Assuming admin email is still "readraaofficial@gmail.com"

  if (story.userId === req.userId || isAdmin) {
    req.story = story; // Attach story to request for later use
    next();
  } else {
    return res.status(403).json({ message: "Unauthorized to perform this action on this story" });
  }
}

// authorize comment action middleware
async function authorizeCommentAction(req, res, next) {
  const commentId = parseInt(req.params.commentId, 10);
  const data = readData();
  let foundComment = null;
  let foundStory = null;

  // Find the comment within all stories
  for (const story of data.stories) {
    const comment = (story.comments || []).find(c => c.id === commentId);
    if (comment) {
      foundComment = comment;
      foundStory = story;
      break;
    }
  }

  if (!foundComment) {
    return res.status(404).json({ message: "Comment not found" });
  }

  // Check if user is the comment owner or an admin
  const user = data.users.find(u => u.id === req.userId);
  const isAdmin = user && user.email === "readraaofficial@gmail.com"; // Assuming admin email is still "readraaofficial@gmail.com"

  if (foundComment.userId === req.userId || isAdmin) {
    req.comment = foundComment; // Attach comment to request
    req.story = foundStory; // Attach parent story to request
    next();
  } else {
    return res.status(403).json({ message: "Unauthorized to perform this action on this comment" });
  }
}

// --------- API ROUTES ----------
// --------- AUTH ----------
app.post("/api/register", async (req, res) => {
  console.log("Request body:", req.body);
  let { name, email, password, phoneNumber } = req.body; // Added phoneNumber, use let for name
  const data = readData();

  // Server-side name validation
  if (name.length < 2 || name.length > 15) {
    return res.status(400).json({ message: "Name must be between 2 and 15 characters long." });
  }
  if (!/^[a-zA-Z0-9_*\-^!]+$/.test(name)) {
    return res.status(400).json({ message: "Name can only contain letters, numbers, and the following special characters: _ * - ^ !" });
  }

  // Password validation
  if (password.length < 5 || password.length > 20) {
    return res.status(400).json({ message: "Password must be between 5 and 20 characters long." });
  }

  if (!name || !email || !password) return res.status(400).json({ message: "Missing fields" });

  // Normalize phoneNumber: if it's just a prefix or empty, treat as null
  /* const isJustPrefix = commonPrefixes.some(prefix => prefix === phoneNumber);
  if (isJustPrefix || phoneNumber === "") {
    phoneNumber = null;
  } // Added phoneNumber check */

  if (data.users.find(u => u.email === email)) {
    return res.status(400).json({ message: "Email already registered" });
  }
  // Check phone number uniqueness ONLY if a phone number was actually provided (i.e., not null)
  /* if (phoneNumber !== null) { // Only perform this check if phoneNumber is not null
    if (data.users.some(u => u.phoneNumber === phoneNumber)) { // Use .some() for existence check
      return res.status(400).json({ message: "Phone number already registered" });
    }
  } */
  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now(),
    name,
    email,
    password: hashed,
    // phoneNumber,
    favorites: [],
    viewed: [],
    nameChangeCount: 0, // Initialize name change count
    lastChangeTimestamp: null // Initialize last change timestamp
  };
  console.log("New user created:", newUser); // Debug log
  data.users.push(newUser);
  writeData(data);
  res.json({ message: "User registered successfully" });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const data = readData();
  const user = data.users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: "User not found" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid password" });

  console.log("User logging in:", user); // Debug log
  const isAdmin = user.email === "readraaofficial@gmail.com";
  const token = jwt.sign({ id: user.id, isAdmin }, SECRET, { expiresIn: "6h" });

  res.json({ token, name: user.name, email: user.email, isAdmin, id: user.id });
});

// --- PASSWORD RESET ---
app.post("/api/send-otp", async (req, res) => {
  const { phoneNumber } = req.body;
  const data = readData();
  const user = data.users.find(u => u.phoneNumber === phoneNumber);

  if (!user) {
    return res.status(404).json({ message: "Phone number not found" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  const expiresAt = Date.now() + 5 * 60 * 1000; // OTP valid for 5 minutes

  // Remove any existing OTPs for this user
  data.otps = data.otps.filter(o => o.userId !== user.id);

  data.otps.push({ userId: user.id, otp, expiresAt });
  writeData(data);

  console.log(`OTP for ${phoneNumber}: ${otp}`); // Simulate SMS sending
  res.json({ message: "OTP sent successfully" });
});

app.post("/api/reset-password", async (req, res) => {
  const { phoneNumber, email, otp, newPassword } = req.body; // Added email
  const data = readData();
  let user;

  if (phoneNumber) {
    user = data.users.find(u => u.phoneNumber === phoneNumber);
  } else if (email) {
    user = data.users.find(u => u.email === email);
  }

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const storedOtp = data.otps.find(o => o.userId === user.id && o.otp === otp);

  if (!storedOtp || storedOtp.expiresAt < Date.now()) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  // Remove the used OTP
  data.otps = data.otps.filter(o => o.userId !== user.id || o.otp !== otp);

  const hashedNewPassword = await bcrypt.hash(newPassword, 10);
  user.password = hashedNewPassword;
  writeData(data);

  res.json({ message: "Password reset successfully" });
});

app.post("/api/send-otp-email", async (req, res) => {
  const { email } = req.body;
  const data = readData();
  const user = data.users.find(u => u.email === email);

  if (!user) {
    return res.status(404).json({ message: "Email not found" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  const expiresAt = Date.now() + 5 * 60 * 1000; // OTP valid for 5 minutes

  // Remove any existing OTPs for this user
  data.otps = data.otps.filter(o => o.userId !== user.id);

  data.otps.push({ userId: user.id, otp, expiresAt });
  writeData(data);

  console.log(`OTP for ${email}: ${otp}`); // Simulate email sending
  res.json({ message: "OTP sent to email successfully" });
});

// --------- USER DATA ----------
app.get("/api/profile", auth, (req, res) => {
  const data = readData();
  const user = data.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ message: "User not found" });

  const isAdmin = user.email === "readraaofficial@gmail.com";
  res.json({ name: user.name, email: user.email, favorites: user.favorites || [], viewed: user.viewed || [], isAdmin, id: user.id, avatarUrl: user.avatarUrl });
});

// Update user avatar
app.put("/api/profile/avatar", auth, (req, res) => {
  const { avatarUrl } = req.body;
  if (!avatarUrl) {
    return res.status(400).json({ message: "Missing avatarUrl" });
  }

  const data = readData();
  const user = data.users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  user.avatarUrl = avatarUrl;
  writeData(data);

  res.json({ message: "Avatar updated successfully", avatarUrl: user.avatarUrl });
});

// Update user name
app.put("/api/profile/name", auth, (req, res) => {
  let { newName } = req.body; // Use let to allow modification

  // Server-side name validation
  newName = newName.trim(); // Trim leading/trailing spaces
  if (newName.length < 2 || newName.length > 20) {
    return res.status(400).json({ message: "Name must be between 2 and 20 characters long." });
  }
  if (!/^[a-zA-Z0-9\s\-\'\.]+$/.test(newName)) { // Allowed characters
    return res.status(400).json({ message: "Name can only contain letters, numbers, spaces, hyphens, apostrophes, and periods." });
  }
  if (/\s\s+/.test(newName)) { // No consecutive spaces
    return res.status(400).json({ message: "Name cannot contain consecutive spaces." });
  }

  if (!newName || newName.trim() === "") { // This check is now redundant but harmless
    return res.status(400).json({ message: "New name cannot be empty" });
  }

  const data = readData();
  const user = data.users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // Allow admin to change name unlimited times
  if (req.isAdmin) {
    user.name = newName.trim();
    writeData(data);
    return res.json({
      message: "Admin name updated successfully (unlimited changes).",
      name: user.name,
      nameChangeCount: -1, // Indicate unlimited changes for admin
      lastChangeTimestamp: null,
      remainingChanges: -1 // Indicate unlimited changes for admin
    });
  }

  // Initialize nameChangeCount and lastChangeTimestamp if they don't exist
  if (user.nameChangeCount === undefined) user.nameChangeCount = 0;
  if (user.lastChangeTimestamp === undefined) user.lastChangeTimestamp = null;

  const now = Date.now();
  const thirtyDays = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

  let currentNameChangeCount = user.nameChangeCount;
  let currentLastChangeTimestamp = user.lastChangeTimestamp;

  // Check if 30 days have passed since last reset
  if (currentLastChangeTimestamp && (now - currentLastChangeTimestamp > thirtyDays)) {
    currentNameChangeCount = 0; // Reset count if 30 days passed
    currentLastChangeTimestamp = null; // Reset timestamp as well
  }

  // Check name change limit (3 times in 30 days)
  if (currentNameChangeCount >= 3) {
    return res.status(403).json({ message: "Name can only be changed three times every 30 days." });
  }

  user.name = newName.trim();
  user.nameChangeCount = currentNameChangeCount + 1; // Use the local variable for increment
  user.lastChangeTimestamp = now;
  writeData(data);

  const remainingChanges = 3 - user.nameChangeCount; // Calculate remaining changes

  res.json({
    message: "Name updated successfully",
    name: user.name,
    nameChangeCount: user.nameChangeCount,
    lastChangeTimestamp: user.lastChangeTimestamp,
    remainingChanges: remainingChanges // Add this
  });
});

// Get user name change info
app.get("/api/user/name-changes-info", auth, (req, res) => {
  const data = readData();
  const user = data.users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // Initialize if not present (for older user data)
  if (user.nameChangeCount === undefined) user.nameChangeCount = 0;
  if (user.lastChangeTimestamp === undefined) user.lastChangeTimestamp = null;

  const now = Date.now();
  const thirtyDays = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

  let currentNameChangeCount = user.nameChangeCount;
  let currentLastChangeTimestamp = user.lastChangeTimestamp;

  // Check if 30 days have passed since last reset
  if (currentLastChangeTimestamp && (now - currentLastChangeTimestamp > thirtyDays)) {
    currentNameChangeCount = 0; // Reset count if 30 days passed
    currentLastChangeTimestamp = null; // Reset timestamp as well
  }

  const remainingChanges = 3 - currentNameChangeCount; // Use 3 for the limit

  // Calculate reset date
  let resetDate = null;
  if (currentLastChangeTimestamp) {
    resetDate = new Date(currentLastChangeTimestamp + thirtyDays).toISOString();
  } else if (currentNameChangeCount === 0) {
    // If no changes yet, and count is 0, reset date is 30 days from now (effectively)
    // Or, more accurately, no reset needed until a change is made.
    // For display purposes, we can say "resets after first change" or similar.
    // For now, let's keep it null if no changes have been made.
  }

  res.json({
    remainingChanges: remainingChanges,
    nameChangeCount: currentNameChangeCount,
    lastChangeTimestamp: currentLastChangeTimestamp,
    resetDate: resetDate
  });
});

// Add favorite
app.post("/api/favorites", auth, (req, res) => {
  const { pdf } = req.body;
  if (!pdf) return res.status(400).json({ message: "Missing pdf title" });
  const data = readData();
  const user = data.users.find(u => u.id === req.userId);
  if (!user.favorites) user.favorites = [];
  if (!user.favorites.includes(pdf)) {
    user.favorites.push(pdf);
    writeData(data);
  }
  res.json({ favorites: user.favorites });
});

// Remove single favorite
app.delete("/api/favorites/:title", auth, (req, res) => {
  const title = decodeURIComponent(req.params.title);
  const data = readData();
  const user = data.users.find(u => u.id === req.userId);
  user.favorites = (user.favorites || []).filter(f => f !== title);
  writeData(data);
  res.json({ favorites: user.favorites });
});

// Clear all favorites
app.delete("/api/favorites", auth, (req, res) => {
  const data = readData();
  const user = data.users.find(u => u.id === req.userId);
  user.favorites = [];
  writeData(data);
  res.json({ message: "Favorites cleared" });
});

// Get list of PDFs by category
app.get("/api/pdfs", (req, res) => {
  const pdfsDir = path.join(__dirname, "pdfs");
  fs.readdir(pdfsDir, { withFileTypes: true }, (err, dirents) => {
    if (err) {
      console.error("Error reading pdfs directory:", err);
      return res.status(500).json({ message: "Error fetching PDFs" });
    }

    const categories = dirents
      .filter(dirent => dirent.isDirectory())
      .map(dirent => {
        const categoryName = dirent.name;
        const categoryPath = path.join(pdfsDir, categoryName);
        const files = fs.readdirSync(categoryPath);

        const pdfs = files
          .filter(file => file.toLowerCase().endsWith("_light.pdf"))
          .map(file => {
            const baseName = file.replace(/_light\.pdf$/i, '');
            return {
              title: baseName.replace(/_/g, ' '),
              filePath: `/pdfs/${categoryName}/${file}`,
              description: "A concise summary of key concepts.",
              baseName: `/pdfs/${categoryName}/${baseName}`
            };
          });

        return { name: categoryName.replace(/_/g, ' '), pdfs };
      });

    res.json({ categories });
  });
});

// Get list of PDFs for the home page by category
app.get("/api/home_pdfs", (req, res) => {
  const homePdfsDir = path.join(__dirname, "home_pdfs");
  fs.readdir(homePdfsDir, { withFileTypes: true }, (err, dirents) => {
    if (err) {
      console.error("Error reading home_pdfs directory:", err);
      return res.status(500).json({ message: "Error fetching home page PDFs" });
    }

    const categories = dirents
      .filter(dirent => dirent.isDirectory())
      .map(dirent => {
        const categoryName = dirent.name;
        const categoryPath = path.join(homePdfsDir, categoryName);
        const files = fs.readdirSync(categoryPath);

        const pdfs = files
          .filter(file => file.toLowerCase().endsWith("_light.pdf"))
          .map(file => {
            const baseName = file.replace(/_light\.pdf$/i, '');
            return {
              title: baseName.replace(/_/g, ' '),
              filePath: `/home_pdfs/${categoryName}/${file}`,
              description: "A concise summary of key concepts.",
              baseName: `/home_pdfs/${categoryName}/${baseName}`
            };
          });

        return { name: categoryName.replace(/_/g, ' '), pdfs };
      });

    res.json({ categories });
  });
});

// --------- STORIES ----------
app.post("/api/stories", auth, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ message: "Missing story title or content" });
  }

  const data = readData();
  const user = data.users.find(u => u.id === req.userId);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  if (!data.stories) {
    data.stories = [];
  }

  const newStory = {
    id: Date.now(),
    userId: req.userId,
    author: user.name,
    avatarUrl: user.avatarUrl, // Save the user's avatar at the time of posting
    title,
    content,
    createdAt: new Date().toISOString(),
    comments: [] // Initialize comments array
  };

  data.stories.push(newStory);
  writeData(data);

  res.status(201).json({ message: "Story posted successfully", story: newStory });
});

app.get("/api/stories", (req, res) => {
  const data = readData();
  const storiesWithAdminStatus = (data.stories || []).map(story => {
    const user = data.users.find(u => u.id === story.userId);
    const isAdmin = user ? user.email === "readraaofficial@gmail.com" : false; // Determine if author is admin
    const reactions = story.reactions || {};
    const reactionCounts = Object.keys(reactions).reduce((acc, emoji) => {
      if (Array.isArray(reactions[emoji])) {
        acc[emoji] = reactions[emoji].length;
      } else if (typeof reactions[emoji] === 'number') {
        acc[emoji] = reactions[emoji];
      }
      return acc;
    }, {});
    const commentCount = (story.comments || []).length; // Get comment count
    return { ...story, reactions: reactionCounts, isAdmin, commentCount }; // Add isAdmin and commentCount to story object
  });
  const sortedStories = storiesWithAdminStatus.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ stories: sortedStories });
});

app.delete("/api/stories/:id", auth, authorizeStoryAction, (req, res) => {
  const storyId = parseInt(req.params.id, 10);
  const data = readData();
  const storyIndex = data.stories.findIndex(s => s.id === storyId);

  if (storyIndex === -1) {
    return res.status(404).json({ message: "Story not found" });
  }

  data.stories.splice(storyIndex, 1);
  writeData(data);

  res.json({ message: "Story deleted successfully" });
});

app.put("/api/stories/:id", auth, authorizeStoryAction, (req, res) => {
  const storyId = parseInt(req.params.id, 10);
  const { title, content } = req.body;

  if (!title || !content) {
    return res.status(400).json({ message: "Missing story title or content" });
  }

  const data = readData();
  const storyIndex = data.stories.findIndex(s => s.id === storyId);

  // story is already attached to req.story by authorizeStoryAction, but we need the index
  if (storyIndex === -1) { // Should not happen if authorizeStoryAction passed
    return res.status(404).json({ message: "Story not found" });
  }

  data.stories[storyIndex].title = title;
  data.stories[storyIndex].content = content;
  data.stories[storyIndex].updatedAt = new Date().toISOString();
  writeData(data);

  res.json({ message: "Story updated successfully", story: data.stories[storyIndex] });
});

app.post('/api/stories/:id/react', auth, (req, res) => {
    try {
        const storyId = parseInt(req.params.id, 10);
        const { emoji } = req.body;
        const userId = req.userId;
        const data = readData();
        const story = data.stories.find(s => s.id === storyId);

        if (!story) {
            return res.status(404).json({ message: "Story not found" });
        }

        if (!story.reactions || typeof story.reactions !== 'object') {
            story.reactions = {};
        }

        // Convert any old number-based reactions to the new array-based format
        for (const e in story.reactions) {
            if (typeof story.reactions[e] === 'number') {
                story.reactions[e] = [];
            }
        }

        let userPreviousReaction = null;
        for (const e in story.reactions) {
            if (Array.isArray(story.reactions[e]) && story.reactions[e].includes(userId)) {
                userPreviousReaction = e;
                break;
            }
        }

        if (userPreviousReaction) {
            const index = story.reactions[userPreviousReaction].indexOf(userId);
            story.reactions[userPreviousReaction].splice(index, 1);

            if (userPreviousReaction !== emoji) {
                if (!Array.isArray(story.reactions[emoji])) {
                    story.reactions[emoji] = [];
                }
                story.reactions[emoji].push(userId);
            }
        } else {
            if (!Array.isArray(story.reactions[emoji])) {
                story.reactions[emoji] = [];
            }
            story.reactions[emoji].push(userId);
        }

        writeData(data);

        const storyWithReactionCounts = {
            ...story,
            reactions: Object.keys(story.reactions).reduce((acc, currentEmoji) => {
                if (Array.isArray(story.reactions[currentEmoji])) {
                    acc[currentEmoji] = story.reactions[currentEmoji].length;
                }
                return acc;
            }, {})
        };

        res.json(storyWithReactionCounts);
    } catch (error) {
        console.error("Error in /api/stories/:id/react:", error);
        res.status(500).json({ message: "An internal server error occurred while processing your reaction." });
    }
});

// API to get comments for a story
app.get("/api/stories/:id/comments", (req, res) => {
  const storyId = parseInt(req.params.id, 10);
  const data = readData();
  const story = data.stories.find(s => s.id === storyId);

  if (!story) {
    return res.status(404).json({ message: "Story not found" });
  }

  const commentsWithAdminStatus = (story.comments || []).map(comment => {
    const user = data.users.find(u => u.id === comment.userId);
    const isAdmin = user ? user.email === "readraa@gmail.com" : false;
    return { ...comment, isAdmin };
  });

  // Sort comments: admin comments first, then by createdAt in descending order (newest first)
  const sortedComments = commentsWithAdminStatus.sort((a, b) => {
    if (a.isAdmin && !b.isAdmin) return -1; // a is admin, b is not, a comes first
    if (!a.isAdmin && b.isAdmin) return 1;  // b is admin, a is not, b comes first
    return new Date(b.createdAt) - new Date(a.createdAt); // Sort by date for non-admins or both admins
  });

  res.json({ comments: sortedComments });
});

// API to add a comment to a story
app.post("/api/stories/:id/comments", auth, (req, res) => {
  const storyId = parseInt(req.params.id, 10);
  const { text } = req.body;

  if (!text) {
    return res.status(400).json({ message: "Comment text is required" });
  }

  const data = readData();
  const story = data.stories.find(s => s.id === storyId);
  const user = data.users.find(u => u.id === req.userId);

  if (!story) {
    return res.status(404).json({ message: "Story not found" });
  }
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  if (!story.comments) {
    story.comments = [];
  }

  const newComment = {
    id: Date.now(),
    userId: user.id,
    author: user.name,
    avatarUrl: user.avatarUrl,
    text,
    createdAt: new Date().toISOString()
  };

  story.comments.push(newComment);
  writeData(data);

  res.status(201).json({ message: "Comment added", comment: newComment, comments: story.comments });
});

// API to delete a comment
app.delete("/api/comments/:commentId", auth, authorizeCommentAction, (req, res) => {
  const commentId = parseInt(req.params.commentId, 10);
  const data = readData();
  const story = data.stories.find(s => s.id === req.story.id); // Use the story attached by middleware

  if (!story) {
    return res.status(404).json({ message: "Story not found (should not happen)" });
  }

  const commentIndex = (story.comments || []).findIndex(c => c.id === commentId);

  if (commentIndex === -1) {
    return res.status(404).json({ message: "Comment not found" });
  }

  story.comments.splice(commentIndex, 1);
  writeData(data);

  res.json({ message: "Comment deleted successfully" });
});

// API to update a comment
app.put("/api/comments/:commentId", auth, authorizeCommentAction, (req, res) => {
  const commentId = parseInt(req.params.commentId, 10);
  const { text } = req.body;

  if (!text) {
    return res.status(400).json({ message: "Comment text is required" });
  }

  const data = readData();
  const story = data.stories.find(s => s.id === req.story.id); // Use the story attached by middleware

  if (!story) {
    return res.status(404).json({ message: "Story not found (should not happen)" });
  }

  const commentIndex = (story.comments || []).findIndex(c => c.id === commentId);

  if (commentIndex === -1) {
    return res.status(404).json({ message: "Comment not found" });
  }

  story.comments[commentIndex].text = text;
  story.comments[commentIndex].updatedAt = new Date().toISOString(); // Add an updatedAt timestamp
  writeData(data);

  res.json({ message: "Comment updated successfully", comment: story.comments[commentIndex] });
});

// --------- DRAFTS ----------
app.post("/api/stories/draft", auth, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ message: "Missing draft title or content" });
  }

  const data = readData();
  const user = data.users.find(u => u.id === req.userId);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const newDraft = {
    id: Date.now(),
    userId: req.userId,
    author: user.name,
    title,
    content,
    createdAt: new Date().toISOString()
  };

  data.drafts.push(newDraft);
  writeData(data);

  res.status(201).json({ message: "Draft saved successfully", draft: newDraft });
});

app.get("/api/users/:userId/drafts", auth, (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  if (req.userId !== userId) {
    return res.status(403).json({ message: "Unauthorized" });
  }
  const data = readData();
  const userDrafts = data.drafts.filter(d => d.userId === userId);

  const draftsWithAdminStatus = userDrafts.map(draft => {
    const user = data.users.find(u => u.id === draft.userId);
    const isAdmin = user ? user.email === "readraaofficial@gmail.com" : false; // Determine if author is admin
    return { ...draft, isAdmin }; // Add isAdmin to draft object
  });

  res.json({ drafts: draftsWithAdminStatus });
});

app.put("/api/stories/draft/:draftId", auth, (req, res) => {
  const draftId = parseInt(req.params.draftId, 10);
  const { title, content } = req.body;

  if (!title || !content) {
    return res.status(400).json({ message: "Missing draft title or content" });
  }

  const data = readData();
  const draftIndex = data.drafts.findIndex(d => d.id === draftId);

  if (draftIndex === -1) {
    return res.status(404).json({ message: "Draft not found" });
  }

  if (data.drafts[draftIndex].userId !== req.userId) {
    return res.status(403).json({ message: "Unauthorized" });
  }

  data.drafts[draftIndex].title = title;
  data.drafts[draftIndex].content = content;
  data.drafts[draftIndex].updatedAt = new Date().toISOString();
  writeData(data);

  res.json({ message: "Draft updated successfully", draft: data.drafts[draftIndex] });
});

app.delete("/api/stories/draft/:draftId", auth, (req, res) => {
  const draftId = parseInt(req.params.draftId, 10);
  const data = readData();
  const draftIndex = data.drafts.findIndex(d => d.id === draftId);

  if (draftIndex === -1) {
    return res.status(404).json({ message: "Draft not found" });
  }

  if (data.drafts[draftIndex].userId !== req.userId) {
    return res.status(403).json({ message: "Unauthorized" });
  }

  data.drafts.splice(draftIndex, 1);
  writeData(data);

  res.json({ message: "Draft deleted successfully" });
});

// --------- SEARCH ----------
app.get("/api/search", (req, res) => {
  const query = req.query.q ? req.query.q.toLowerCase() : "";
  if (!query) {
    return res.json({ results: [] });
  }

  const getAllPdfs = (baseDir, routePrefix) => {
    let allPdfs = [];
    try {
      const dirents = fs.readdirSync(baseDir, { withFileTypes: true });
      dirents
        .filter(dirent => dirent.isDirectory())
        .forEach(dirent => {
          const categoryName = dirent.name;
          const categoryPath = path.join(baseDir, categoryName);
          const files = fs.readdirSync(categoryPath);

          const pdfs = files
            .filter(file => file.toLowerCase().endsWith(".pdf"))
            .map(file => {
              const title = path.parse(file).name.replace(/_light|_dark/i, '').replace(/_/g, ' ');
              return {
                title: title,
                filePath: `${routePrefix}/${categoryName}/${file}`,
                description: "A concise summary of key concepts.",
                category: categoryName.replace(/_/g, ' ')
              };
            });
          allPdfs = allPdfs.concat(pdfs);
        });
    } catch (err) {
      console.error(`Error reading directory for search: ${baseDir}`, err);
    }
    return allPdfs;
  };

  const libraryPdfs = getAllPdfs(path.join(__dirname, "pdfs"), "/pdfs");
  const homePdfs = getAllPdfs(path.join(__dirname, "home_pdfs"), "/home_pdfs");

  const combinedPdfs = [...libraryPdfs, ...homePdfs];
  
  // Remove duplicates based on title
  const uniquePdfs = Array.from(new Map(combinedPdfs.map(pdf => [pdf.title.toLowerCase(), pdf])).values());

  const searchResults = uniquePdfs.filter(pdf => 
    pdf.title.toLowerCase().includes(query)
  );

  res.json({ results: searchResults });
});

// --------- STATIC ASSETS & SPA FALLBACK ----------
// Serve index.html for the root path with correct Content-Type
app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  console.log(`Attempting to send index.html from: ${indexPath}`);
  res.sendFile(indexPath, (err) => {
    if (err) {
      console.error('Error sending index.html:', err);
      res.status(500).send('Error loading page.');
    } else {
      console.log('index.html sent successfully.');
    }
  });
});

// Serve other static assets from the public directory
app.use(express.static(path.join(__dirname, "public")));
app.use("/pdfs", express.static(path.join(__dirname, "pdfs")));
app.use("/home_pdfs", express.static(path.join(__dirname, "home_pdfs")));


// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error handler caught an error:", err.stack);
  res.status(500).json({ message: "An unexpected server error occurred." });
});

app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));