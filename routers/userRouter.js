const router = require("express").Router();
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

router.post("/register", async (req, res) => {
    try {
        const { name, classLevel, stream, phone, email, password, passwordVerify } = req.body;

        // Check if all required fields are provided
        if (!name || !classLevel || !stream || !phone || !email || !password || !passwordVerify) {
            return res.status(400).json({ errorMessage: "Please enter all required fields." });
        }

        // Validate password length
        if (password.length < 6) {
            return res.status(400).json({ errorMessage: "Please enter a password of at least 6 characters." });
        }

        // Check if password and passwordVerify match
        if (password !== passwordVerify) {
            return res.status(400).json({ errorMessage: "Passwords do not match." });
        }

        // Check if email is already in use
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ errorMessage: "An account with this email already exists." });
        }

        // Check if phone number is already in use
        const existingPhone = await User.findOne({ phone });
        if (existingPhone) {
            return res.status(400).json({ errorMessage: "An account with this phone number already exists." });
        }

        // Hash the password
        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        // Save the new user account to the database
        const newUser = new User({
            name,
            classLevel,
            stream,
            phone,
            email,
            passwordHash
        });

        const savedUser = await newUser.save();

        // Create and send JWT token
        const token = jwt.sign(
            {
                user: savedUser._id,
            },
            process.env.JWT_SECRET_KEY
        );

        // Send the token in HTTP only cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            sameSite: "none"
        }).send();

    } catch (err) {
        console.error(err);
        res.status(500).send();
    }
});
// Login

// Login
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate
        if (!email || !password) {
            return res.status(400).json({ errorMessage: "Please enter all required fields." });
        }

        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(400).json({ errorMessage: "Wrong email or password." });
        }

        const passwordCorrect = await bcrypt.compare(password, existingUser.passwordHash);
        if (!passwordCorrect) {
            return res.status(401).json({ errorMessage: "Wrong email or password" });
        }

        // Log the user in
        const token = jwt.sign(
            {
                user: existingUser._id,
            },
            process.env.JWT_SECRET_KEY
        );

        // Send the token in HTTP-only cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            sameSite: "none"
        }).send();

    } catch (err) {
        console.error(err);
        res.status(500).send();
    }
});
// To logout

router.get("/logout", (req, res) => {
    res.cookie("token", "", {
        httpOnly: true,
        expires: new Date(0),
        secure: true,
        sameSite: "none"
    }).send();
});

router.get("/loggedIn", (req, res) => {
    try {
        const token = req.cookies.token;
        if(!token) return res.json(false);

        jwt.verify(token, process.env.JWT_SECRET_KEY);
        res.send(true);
    } catch (err) {
        res.json(false);
    }
});

router.get("/user", async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) return res.status(401).json({ error: "Unauthorized" });

        const verified = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const user = await User.findById(verified.user);

        if (!user) return res.status(404).json({ error: "User not found" });

        res.json(user);
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

router.put("/user/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const { name, classLevel, stream, phone, email } = req.body;

        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ errorMessage: "User not found" });
        }

        user.name = name;
        user.classLevel = classLevel;
        user.stream = stream;
        user.phone = phone;
        user.email = email;

        const updatedUser = await user.save();
        res.json(updatedUser);
    } catch (err) {
        console.error(err);
        res.status(500).send();
    }
});

module.exports = router;