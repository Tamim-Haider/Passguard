# PassGuard — Password Strength Analyzer

PassGuard is a sleek, professional-grade web application designed to analyze password security in real-time. It provides users with a comprehensive breakdown of password strength, entropy, and potential vulnerabilities while ensuring 100% privacy through client-side processing.

## 🚀 Features

- **Real-time Scoring:** Instant feedback as you type, featuring a 5-tier visual strength meter (Very Weak to Very Strong).
- **Entropy Calculation:** Scientifically measures password strength in bits based on the character pool and length.
- **Crack Time Estimation:** Provides an estimate of how long it would take to brute-force the password at a rate of 10 billion guesses per second.
- **Comprehensive Security Checks:** - Length analysis (8+, 12+, 16+, and 20+ characters).
    - Character diversity (Uppercase, Lowercase, Numbers, Symbols).
    - Common password detection (Checks against a built-in breach dictionary).
    - Pattern detection (Flags repeated characters and keyboard sequences).
- **Passphrase Generator:** Encourages better security habits by generating long, memorable, four-word passphrases.
- **Actionable Suggestions:** Dynamically generates tips to harden your specific password.
- **Privacy First:** Built with a "Security-by-Design" approach—no data is sent to a server. Everything happens locally in your browser.

## 🛠️ Technology Stack

- **HTML5:** Semantic structure for the analyzer interface.
- **CSS3:** Modern, "Cyberpunk-inspired" dark UI featuring:
    - CSS Variables for easy skinning.
    - Backdrop filters and glassmorphism.
    - Fully responsive grid and flexbox layouts.
    - Custom animations for a professional desktop-app feel.
- **Vanilla JavaScript:** - Real-time event listeners for input analysis.
    - Complex regex-based pattern and sequence detection.
    - Mathematical entropy calculations.

## 📂 File Structure

- `index.html`: The main structural file containing the UI components and analyzer layout.
- `style.css`: The styling engine, containing the dark theme, grid backgrounds, and responsive media queries.
- `script.js`: The core logic engine responsible for scoring, entropy math, and UI updates.

## 📋 Security Methodology

The strength score is calculated out of 10 points based on the following criteria:
1. **Length:** Incremental points at 8, 12, 16, and 20 characters.
2. **Diversity:** Points for including lowercase, uppercase, numbers, and symbols.
3. **Complexity:** Extra points for multiple numbers and multiple symbols.
4. **Penalties:** Drastic score reductions for common passwords (e.g., "123456") or dominant sequential/repetitive patterns.

## 🖥️ Getting Started

1. Clone or download the project files.
2. Ensure `index.html`, `style.css`, and `script.js` are in the same directory.
3. Open `index.html` in any modern web browser.

---
*Built for security awareness and education.*
