import javax.swing.*;//imports all classes from javax.swing package such as JFrame, JPanel, JButton, JTextArea, JLabel, JComboBox, JOptionPane, SwingUtilities
import javax.swing.border.*;//imports all classes from javax.swing.border package such as EmptyBorder, TitledBorder
import java.awt.*;//provides lower level classes for GUI components like Color, Font, BorderLayout, FlowLayout, Cursor
import java.awt.event.*;//imports all event handling classes like ActionEvent, MouseEvent
import java.util.*;//imports all utility classes like Map, HashMap, Set, HashSet, ArrayList
import java.util.List;//imports List interface specifically
import java.util.regex.*;//imports classes for pattern matching
//C0-05 CONCEPT
public class ScamDetectorGUI extends JFrame {   
    // ========== SCAM PATTERNS - EDIT THESE TO ADD/REMOVE PATTERNS ==========
    // CO-06 CONCEPT
    private static final Map<String, String> SCAM_PATTERNS = new LinkedHashMap<>();//hashmap used to store and manage data in key-value pairs   
    static {
        //defining various scam patterns with regex
        SCAM_PATTERNS.put("Urgency/Pressure", 
            "urgent(ly)?|immediate(ly)?|act now|expire(s|d)? (today|soon)|last chance|final notice|hurry|quick(ly)?");    
        SCAM_PATTERNS.put("Prize/Lottery Scam", 
            "you('ve| have) won|congratulations.*(won|winner)|claim (your )?(prize|reward)|lottery winner|free (money|cash|gift card)");   
        SCAM_PATTERNS.put("Account Security Scam", 
            "(verify|confirm|update) (your )?account|account (suspended|locked|blocked|frozen)|unusual activity|security alert");        
        SCAM_PATTERNS.put("Phishing Link", 
            "click (here|this link|below)|verify.*link|follow (this|the) link|download (now|attachment)");       
        SCAM_PATTERNS.put("Personal Info Request", 
            "(send|provide|enter|confirm) (your )?(password|ssn|social security|bank account|credit card|pin)");       
        SCAM_PATTERNS.put("Authority Impersonation", 
            "(irs|fbi|police|social security administration|government).*(notice|warning)|" +
            "(amazon|microsoft|apple|google|paypal|netflix|bank) (security|support)");       
        SCAM_PATTERNS.put("Threat/Fear Tactics", 
            "(legal|criminal) action|arrest warrant|(will be|get) arrested|fine of \\$|lawsuit|your account will be (closed|terminated)");   
        SCAM_PATTERNS.put("Too Good to Be True", 
            "100% (free|guaranteed)|no (catch|risk|strings)|make \\$\\d+.(per|a) (day|week)|work from home.\\$|easy money");       
        SCAM_PATTERNS.put("Crypto/Investment Scam", 
            "send.*bitcoin|crypto.*giveaway|double your (bitcoin|crypto)|guaranteed returns|\\d+% (daily|weekly) (return|profit)");       
        SCAM_PATTERNS.put("Romance Scam", 
            "send (me )?money|wire money|transfer (money|funds)|emergency.*money|stuck in.*country|help me (travel|return)");        
        SCAM_PATTERNS.put("Delivery Scam", 
            "(package|parcel|delivery) (pending|delayed|held)|unable to deliver|confirm.*delivery|track your package");        
        SCAM_PATTERNS.put("Tax/Refund Scam", 
            "tax (refund|rebate)|refund of \\$|stimulus (payment|check)|unclaimed (money|refund)");       
        SCAM_PATTERNS.put("Job Scam", 
            "hired.pay.*fee|job offer.*pay.*fee|work from home.(easy|simple)|no experience.*\\$\\d+|be your own boss");
        SCAM_PATTERNS.put("Suspicious Contact", 
            "(call|text|contact).(immediately|urgent|now)|call us back|whatsapp.\\+?\\d+");
    }    
    // ========== RISK LEVEL SETTINGS ==========
    //public static final implies that these are fixed values and cannot be changed
    //scores to calculate risk level
    private static final int CRITICAL_SCORE = 5;
    private static final int HIGH_SCORE = 3;
    private static final int MEDIUM_SCORE = 2;
    private static final int LOW_SCORE = 1;   
    private static final int CRITICAL_CATEGORIES = 4;
    private static final int HIGH_CATEGORIES = 3;
    private static final int MEDIUM_CATEGORIES = 2;   
    // ========== UI COLORS ==========
    //defining colors used in the GUI
    private static final Color BG_DARK = new Color(30, 30, 30);
    private static final Color BG_MEDIUM = new Color(40, 40, 50);
    private static final Color BG_LIGHT = new Color(45, 45, 55);
    private static final Color TEXT_COLOR = new Color(220, 220, 220);
    private static final Color ACCENT_BLUE = new Color(100, 181, 246);
    //defining colors for different risk levels
    private static final Color RISK_CRITICAL = new Color(231, 76, 60);
    private static final Color RISK_HIGH = new Color(230, 126, 34);
    private static final Color RISK_MEDIUM = new Color(241, 196, 15);
    private static final Color RISK_LOW = new Color(52, 152, 219);
    private static final Color RISK_SAFE = new Color(46, 204, 113);    
    // ========== GUI COMPONENTS ==========
    private JTextArea messageArea;//declares a text area for user to input message
    private JTextArea resultArea;//used to show the scan results
    private JLabel riskLabel;//used to display the risk level
    private JPanel riskPanel;//holds the risk level label and changes color based on risk
    private JComboBox<String> sortComboBox;//declares a drop down menu for the user to sort through results
    private ScanResult currentResult;//holds the result of the current scan
    //CO-04 CONCEPT
    // ========== CONSTRUCTOR ==========
    public ScamDetectorGUI() //constructor method to initialize the GUI
    {
        setTitle("Scam Message Detector");//sets the title of the window
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);//ensures the application exits when the window is closed
        setSize(900, 700);//sets the initial size of the window
        setLocationRelativeTo(null);//centers the window on the screen
        getContentPane().setBackground(BG_DARK);//sets the background color of the window
        createUI();//calls method to create the user interface
    }    
    // ========== CREATE USER INTERFACE ==========
    private void createUI()//method to set up the GUI components
    {
        setLayout(new BorderLayout(10, 10));//sets the layout manager for the main frame with gaps between components
        add(createHeader(), BorderLayout.NORTH);//adds the header panel to the top of the frame
        add(createMainPanel(), BorderLayout.CENTER);//adds the main panel to the center of the frame
        add(createFooter(), BorderLayout.SOUTH);//adds the footer panel to the bottom of the frame
    }   
    private JPanel createHeader()//method to create the header panel
    {
        JPanel panel = new JPanel();//creates a new panel
        panel.setBackground(new Color(25, 25, 35));//sets the background color of the panel
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));//adds padding around the panel       
        JLabel title = new JLabel(" SCAM DETECTOR");//creates a label for the title
        title.setFont(new Font("Arial", Font.BOLD, 24));//sets the font of the title
        title.setForeground(ACCENT_BLUE);//sets the color of the title text
        panel.add(title);//adds the title label to the panel    
        return panel;
    }    
    private JPanel createMainPanel()//method to create the main content panel 
    {
        JPanel panel = new JPanel(new BorderLayout(10, 10));//creates a new panel with border layout
        panel.setBackground(BG_DARK);//sets the background color of the panel
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));//adds padding around the panel
        panel.add(createInputPanel(), BorderLayout.NORTH);//adds the input panel to the top of the main panel
        panel.add(createResultsPanel(), BorderLayout.CENTER);//adds the results panel to the center of the main panel
        return panel;
    }
    private JPanel createInputPanel()//method to create the input panel 
    {
        JPanel panel = new JPanel(new BorderLayout(5, 5));//creates a new panel with border layout
        panel.setBackground(BG_MEDIUM);//sets the background color of the panel
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(ACCENT_BLUE, 2),
            "Enter Message to Scan",
            TitledBorder.CENTER, TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 20),
            ACCENT_BLUE));
        messageArea = new JTextArea(8, 50);
        messageArea.setLineWrap(true);//moves text to next line when it reaches the edge
        messageArea.setWrapStyleWord(true);//ensures words are not split when wrapping
        messageArea.setFont(new Font("Monospaced", Font.PLAIN, 12));//sets a monospaced font for better readability
        messageArea.setBackground(BG_LIGHT);//sets background color of text area
        messageArea.setForeground(TEXT_COLOR);//sets text color
        messageArea.setCaretColor(ACCENT_BLUE);//sets the color of the text cursor
        messageArea.setBorder(new EmptyBorder(5, 5, 5, 5));//adds padding inside the text area
        panel.add(new JScrollPane(messageArea), BorderLayout.CENTER);//adds a scroll pane to the text area for overflow
        panel.add(createButtonPanel(), BorderLayout.SOUTH);//adds the button panel to the bottom of the input panel
        return panel;
    }
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));//creates a new panel with flow layout
        panel.setBackground(BG_MEDIUM);
        JButton scanBtn = createButton(" Scan Message", new Color(76, 175, 80));
        scanBtn.addActionListener(e -> scanMessage());//adds action listener to trigger scan on button click
        JButton checkUrlBtn = createButton(" Check URL", new Color(100, 181, 246));
        checkUrlBtn.addActionListener(e -> checkURL());//adds action listener to check URL scam risk
        JButton clearBtn = createButton(" Clear", new Color(120, 120, 130));//creates a clear button
        clearBtn.addActionListener(e -> clearFields());//adds action listener to clear fields on button click
        panel.add(scanBtn);//adds the scan button to the panel
        panel.add(checkUrlBtn);//adds the check URL button to the panel
        panel.add(clearBtn);//adds the clear button to the panel
        return panel;
    }
    private JButton createButton(String text, Color color) {
        JButton button = new JButton(text);
        button.setFont(new Font("Arial", Font.BOLD, 12));
        button.setBackground(color);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);//removes the focus border when clicked
        button.setBorder(new EmptyBorder(8, 15, 8, 15));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));//changes cursor to hand when hovering over button
        button.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) { button.setBackground(color.darker()); }//darkens button color on hover
            public void mouseExited(MouseEvent e) { button.setBackground(color); }//restores button color when not hovering
        });
        return button;
    }
    private JPanel createResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBackground(BG_MEDIUM);
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(239, 83, 80), 2),
            "Scan Results",
            TitledBorder.CENTER, TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 20),
            new Color(244, 143, 177)));
        // Risk level display
        riskPanel = new JPanel();
        riskPanel.setBackground(new Color(50, 50, 60));
        riskPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        riskLabel = new JLabel("No scan performed yet");
        riskLabel.setFont(new Font("Arial", Font.BOLD, 16));
        riskLabel.setForeground(new Color(180, 180, 180));
        riskPanel.add(riskLabel);
        // Sort options panel
        JPanel sortPanel = createSortPanel();//creates the sorting options panel
        // Details text area
        resultArea = new JTextArea();
        resultArea.setEditable(false);//makes the text area read-only
        resultArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        resultArea.setBackground(BG_LIGHT);
        resultArea.setForeground(TEXT_COLOR);
        resultArea.setBorder(new EmptyBorder(5, 5, 5, 5));
        panel.add(riskPanel, BorderLayout.NORTH);
        panel.add(sortPanel, BorderLayout.SOUTH);
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
        return panel;
    }
    // ========== SORTING PANEL ==========
    private JPanel createSortPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        panel.setBackground(BG_MEDIUM);
        JLabel sortLabel = new JLabel("Sort by:");//creates a label for sorting options
        sortLabel.setFont(new Font("Arial", Font.BOLD, 11));
        sortLabel.setForeground(TEXT_COLOR);
        String[] sortOptions = {//defines sorting options
            "Detection Order",//default order of detection
            "Category (A-Z)",//alphabetical order
            "Category (Z-A)",//alphabetical reverse order
            "Match Length (Shortest First)",//sort by length of matched text
            "Match Length (Longest First)"//sort by length of matched text in reverse order
        };
        sortComboBox = new JComboBox<>(sortOptions);//creates a drop-down menu for sorting options
        sortComboBox.setFont(new Font("Arial", Font.PLAIN, 11));
        sortComboBox.setBackground(BG_LIGHT);
        sortComboBox.setForeground(TEXT_COLOR);
        sortComboBox.addActionListener(e -> {
            if (currentResult != null && !currentResult.matches.isEmpty()) //checks if there are results to sort 
            {
                applySorting();//sorts the results based on selected option
                displayResults(currentResult);//displays the sorted results
            }
        });
        panel.add(sortLabel);//adds the sort label to the panel
        panel.add(sortComboBox);//adds the drop-down menu to the panel
        return panel;
    }
    private JPanel createFooter()//method to create the footer panel 
    {
        JPanel panel = new JPanel();
        panel.setBackground(BG_DARK);
        panel.setBorder(new EmptyBorder(5, 15, 10, 15));
        JLabel footer = new JLabel("Always verify suspicious messages through official channels");//used to display status messages,instructions,or disclaimers
        footer.setFont(new Font("Arial", Font.ITALIC, 10));
        footer.setForeground(new Color(150, 150, 150));
        panel.add(footer);//adds the footer label to the panel
        return panel;
    }
    // ========== CHECK URL FUNCTION ==========
    // Enhanced method to check for URLs and analyze them comprehensively for scam risk
    // Improved with better regex, more detection checks, and detailed analysis
    private void checkURL() {
        String message = messageArea.getText().trim();
        // Enhanced regex pattern to catch URLs with or without http/https
        // Matches: http(s)://domain.com, www.domain.com, and basic domain patterns
        Pattern urlPattern = Pattern.compile(
            "(?:(?:https?://)|(?:www\\.))?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"+
            "(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\\.[a-zA-Z]{2,}"+
            "(?:/[^\\s]*)?" +
            "|" +
            "https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[^\\s]*)?",
            Pattern.CASE_INSENSITIVE);
        Matcher matcher = urlPattern.matcher(message);
        List<String> foundURLs = new ArrayList<>();
        // Collect all URLs found and avoid duplicates
        while (matcher.find()) {
            String url = matcher.group();
            if (!foundURLs.contains(url) && isValidURL(url)) {
                foundURLs.add(url);
            }
        }
        // Show error if no valid URLs found in the message
        if (foundURLs.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "No valid URLs found in the message!",
                "No URLs Detected",
                JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        // Create result object to store URL analysis findings
        ScanResult result = new ScanResult();
        // Analyze each URL found in the message for scam indicators
        for (String url : foundURLs) {
            URLAnalysis analysis = analyzeURL(url);
            result.addURLMatch(analysis.isSuspicious ? "Suspicious URL" : "Safe URL", url, analysis);
        }
        // Calculate overall risk score based on URL analysis results
        int urlRiskScore = 0;
        for (Match match : result.matches) {
            if (match.urlAnalysis != null && match.urlAnalysis.isSuspicious) {
                switch (match.urlAnalysis.riskLevel) {
                    case "HIGH": urlRiskScore += 3; break;
                    case "MEDIUM": urlRiskScore += 2; break;
                    case "LOW": urlRiskScore += 1; break;
                    default: break;
                }
            }
        }
        // Calculate final risk level and display results
        result.calculateRisk(urlRiskScore, foundURLs.size());
        currentResult = result;
        displayResults(result);
        // Show dialog summarizing URL risks found (if any)
        showURLWarnings(result);
    }
    // ========== URL VALIDATION HELPER ==========
    // Validates whether a string is actually a URL (avoids false positives)
    private boolean isValidURL(String url) {
        String lowerURL = url.toLowerCase();
        // Must contain a dot followed by at least 2 letters (basic domain check)
        return lowerURL.matches(".[a-z0-9]\\.[a-z]{2,}.") && 
               !lowerURL.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    }
    // ========== SCAN MESSAGE FUNCTION ==========
    private void scanMessage() {
        String message = messageArea.getText().trim();//used to get the text input from the user and remove leading/trailing whitespace
        //CO-01 CONCEPT
        if (message.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "Please enter a message to scan!",
                "Input Required",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        currentResult = performScan(message);//performs the scan on the input message
        sortComboBox.setSelectedIndex(0); // Reset to detection order
        displayResults(currentResult);
        // Show message-level warning and URL warnings (if any)
        showMessageWarnings(currentResult);
        showURLWarnings(currentResult);
    }
    // ========== MAIN SCANNING LOGIC ==========
    // This method scans the input message for all predefined scam patterns and URLs
    private ScanResult performScan(String message)//method to perform the actual scanning of the message
    {
        ScanResult result = new ScanResult();
        int totalMatches = 0;  // Counter for total pattern matches found
        Set<String> matchedCategories = new HashSet<>();//to track unique categories matched
        // Iterate through each scam pattern in the SCAM_PATTERNS map
        for (Map.Entry<String, String> entry : SCAM_PATTERNS.entrySet())//iterates through each scam pattern defined in the SCAM_PATTERNS map
        {
            String category = entry.getKey();//gets the category name of the scam pattern
            String patternStr = entry.getValue();//gets the regex pattern string
            // Compile regex pattern for case-insensitive matching
            Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);//compiles the regex pattern with case insensitive flag
            Matcher matcher = pattern.matcher(message);//creates a matcher to find occurrences of the pattern in the message
            // Find all pattern occurrences in the message
            while (matcher.find()) {
                String matched = matcher.group().trim();//gets the matched text
                result.addMatch(category, matched);//adds the match to the result object
                totalMatches++;//increments the total match count
                matchedCategories.add(category);//adds the category to the set of matched categories
            }
        }
        // Check for suspicious URLs and add them to results
        checkSuspiciousURLs(message, result);//checks for suspicious URLs in the message and adds them to the result
        // Calculate URL risk score and add to total matches
        int urlRiskScore = 0;
        for (Match match : result.matches) {
            if (match.urlAnalysis != null && match.urlAnalysis.isSuspicious) {
                if (match.urlAnalysis.riskLevel.equals("CRITICAL")) {
                    urlRiskScore += 3;  // CRITICAL URLs add 3 points
                } else if (match.urlAnalysis.riskLevel.equals("HIGH")) {
                    urlRiskScore += 2;  // HIGH risk URLs add 2 points
                } else {
                    urlRiskScore += 1;  // MEDIUM/LOW risk URLs add 1 point
                }
            }
        }
        // Calculate overall risk level based on total matches (patterns + URLs) and unique categories found
        result.calculateRisk(totalMatches + urlRiskScore, matchedCategories.size());//calculates the overall risk level based on all matches found
        
        return result;
    }
    // ========== CHECK FOR SUSPICIOUS URLs ==========
    // This method extracts and analyzes URLs from the message for scam indicators
    private void checkSuspiciousURLs(String message, ScanResult result)// 
    {
        // Create regex pattern to match URLs starting with http:// or https://
        Pattern urlPattern = Pattern.compile(
            "https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[^\\s]*)?",
            Pattern.CASE_INSENSITIVE);
        Matcher matcher = urlPattern.matcher(message);//creates a matcher to find URLs in the message
        // Process each URL found in the message
        while (matcher.find()) {
            String url = matcher.group();//gets the matched URL
            URLAnalysis analysis = analyzeURL(url);//analyzes the URL for scam risk indicators
            if (analysis.isSuspicious) {
                result.addURLMatch("Suspicious URL", url, analysis);//adds the suspicious URL match to the result
            } else {
                result.addURLMatch("Safe URL", url, analysis);//adds the safe URL match to the result
            }
        }
    }
    // ========== URL ANALYSIS METHOD ==========
    // Comprehensive URL analysis with multiple scam indicators and detailed risk assessment
    private URLAnalysis analyzeURL(String url) {
        URLAnalysis analysis = new URLAnalysis(url);//creates new URLAnalysis object
        String lower = url.toLowerCase();//convert to lowercase for pattern matching
        
        // ===== WHITELIST CHECK - KNOWN LEGITIMATE DOMAINS =====
        // If the URL is from a known legitimate company/service, mark as SAFE immediately
        String[] trustedDomains = {
            "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", 
            "linkedin.com", "snapchat.com", "tiktok.com", "reddit.com", "pinterest.com",
            "amazon.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com",
            "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
            "paypal.com", "stripe.com", "visa.com", "mastercard.com",
            "chase.com", "wellsfargo.com", "bofa.com", "citibank.com",
            "netflix.com", "spotify.com", "hulu.com", "disney.com",
            "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
            "dropbox.com", "box.com", "onedrive.com", "icloud.com", "drive.google.com",
            "slack.com", "discord.com", "telegram.org", "whatsapp.com",
            "cdc.gov", "nasa.gov", "usa.gov", "harvard.edu", "mit.edu", "stanford.edu"
        };
        for (String trusted : trustedDomains) {
            if (lower.contains(trusted)) {
                analysis.isSuspicious = false;
                analysis.riskLevel = "SAFE";
                analysis.reasons.add("Legitimate domain: " + trusted);
                return analysis;  // Return immediately - it's safe
            }
        }
        
        // ===== CRITICAL RISK CHECKS =====
        // Check for URL shorteners (CRITICAL RISK) - they hide the true destination
        String[] shortenerServices = {"bit.ly", "tinyurl", "goo.gl", "ow.ly", "is.gd", "short.link", 
                                      "bitly", "shortened", "tiny.cc", "clicky.me"};
        for (String shortener : shortenerServices) {
            if (lower.contains(shortener)) {
                analysis.isSuspicious = true;
                analysis.riskLevel = "CRITICAL";
                analysis.reasons.add("Uses URL shortener '" + shortener + "' (hides true destination)");
                break;
            }
        }
        // Check for punycode domains (CRITICAL RISK) - used in homograph attacks
        if (lower.contains("xn--")) {
            analysis.isSuspicious = true;
            analysis.riskLevel = "CRITICAL";
            analysis.reasons.add("Contains punycode domain (used in homograph phishing attacks)");
        }
        // ===== HIGH RISK CHECKS =====
        // Check for IP address instead of domain (HIGH RISK)
        if (lower.matches(".\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.")) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL")) {
                analysis.riskLevel = "HIGH";
            }
            analysis.reasons.add("Uses IP address instead of domain name (very suspicious)");
        }
        // Check for email-like URL (HIGH RISK) - phishing indicator
        if (lower.contains("@")) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL")) {
                analysis.riskLevel = "HIGH";
            }
            analysis.reasons.add("Contains @ symbol (classic phishing indicator)");
        }
        // Check for excessive URL path complexity (HIGH RISK)
        int slashCount = lower.length() - lower.replace("/", "").length();
        if (slashCount > 5) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL")) {
                analysis.riskLevel = "HIGH";
            }
            analysis.reasons.add("Excessive URL path complexity (may hide destination)");
        }
        
        // Check for impersonation of known companies (HIGH RISK)
        String[] phishingPatterns = {"paypal-", "amazon-", "apple-", "google-", "microsoft-", 
                                     "banking-", "secure-bank", "verify-", "confirm-", 
                                     "facebook-", "instagram-", "twitter-"};
        for (String pattern : phishingPatterns) {
            if (lower.contains(pattern)) {
                analysis.isSuspicious = true;
                if (!analysis.riskLevel.equals("CRITICAL")) {
                    analysis.riskLevel = "HIGH";
                }
                analysis.reasons.add("Contains impersonation pattern (mimics legitimate companies)");
                break;
            }
        }
        // ===== MEDIUM RISK CHECKS =====
        // Check for excessive subdomains (MEDIUM RISK)
        int dotCount = lower.split("\\.", -1).length - 1;
        if (dotCount > 4) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL") && !analysis.riskLevel.equals("HIGH")) {
                analysis.riskLevel = "MEDIUM";
            }
            analysis.reasons.add("Excessive subdomains (unusual domain structure)");
        }
        // Check for multiple dashes (MEDIUM RISK) - common in phishing URLs
        int dashCount = lower.length() - lower.replace("-", "").length();
        if (dashCount >= 3) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL") && !analysis.riskLevel.equals("HIGH")) {
                analysis.riskLevel = "MEDIUM";
            }
            analysis.reasons.add("Multiple dashes in domain (commonly used in phishing)");
        }
        // Check for mixed case (MEDIUM RISK) - potential homograph attack
        if (!lower.equals(url)) {
            int upperCount = (int) url.chars().filter(Character::isUpperCase).count();
            if (upperCount > 3) {
                analysis.isSuspicious = true;
                if (!analysis.riskLevel.equals("CRITICAL") && !analysis.riskLevel.equals("HIGH")) {
                    analysis.riskLevel = "MEDIUM";
                }
                analysis.reasons.add("Mixed case in domain (potential homograph attack)");
            }
        }
        // Check for numeric-heavy domain (MEDIUM RISK)
        String domain = lower.replaceAll("https?://|/.*", "");
        int digitCount = (int) domain.chars().filter(Character::isDigit).count();
        if (digitCount > 5) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL") && !analysis.riskLevel.equals("HIGH")) {
                analysis.riskLevel = "MEDIUM";
            }
            analysis.reasons.add("Domain contains many numbers (suspicious pattern)");
        }
        // ===== LOW RISK CHECKS =====
        
        // Check for suspicious keywords in URL (LOW RISK)
        String[] suspiciousKeywords = {"login", "verify", "confirm", "secure", "account", "update", 
                                       "click", "signin", "sign-in", "authenticate", "validate", 
                                       "password", "credential", "urgent", "action", "billing"};
        for (String keyword : suspiciousKeywords) {
            if (lower.contains(keyword)) {
                if (!analysis.isSuspicious) {
                    analysis.isSuspicious = true;
                    analysis.riskLevel = "LOW";
                }
                analysis.reasons.add("Contains suspicious keyword '" + keyword + "'");
                break;
            }
        }
        // Check for unusual TLD (TOP LEVEL DOMAIN) - LOW RISK
        String[] unusualTLDs = {".tk", ".ml", ".ga", ".cf"};
        for (String tld : unusualTLDs) {
            if (lower.endsWith(tld)) {
                if (!analysis.isSuspicious) {
                    analysis.isSuspicious = true;
                    analysis.riskLevel = "LOW";
                }
                analysis.reasons.add("Uses unusual/free TLD " + tld + " (common in phishing)");
                break;
            }
        }
        // ===== ADDITIONAL FAKE URL DETECTION =====
        // Check for fake banking domain patterns (HIGH RISK)
        String[] bankingFakePatterns = {"bank", "secure", "login", "verify", "confirm", "payment", "checkout"};
        String[] bankNames = {"chase", "wellsfargo", "bofa", "citibank", "paypal", "stripe", "square"};
        for (String bank : bankNames) {
            for (String pattern : bankingFakePatterns) {
                if (lower.contains(bank) && lower.contains(pattern) && !lower.contains(bank + "." + pattern)) {
                    analysis.isSuspicious = true;
                    if (!analysis.riskLevel.equals("CRITICAL")) {
                        analysis.riskLevel = "HIGH";
                    }
                    analysis.reasons.add("Suspicious fake banking domain pattern detected");
                    break;
                }
            }
        }
        // Check for suspicious URL parameters (MEDIUM RISK) - often used to hide destination
        if (lower.contains("?") && (lower.contains("redirect") || lower.contains("url=") || 
            lower.contains("continue=") || lower.contains("returnto") || lower.contains("back="))) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL") && !analysis.riskLevel.equals("HIGH")) {
                analysis.riskLevel = "MEDIUM";
            }
            analysis.reasons.add("Contains suspicious redirect parameters (may hide destination)");
        }
        // Check for encoded/obfuscated URLs (HIGH RISK) - using hex, base64 patterns
        if (lower.matches(".%[0-9a-f]{2}.") || lower.matches(".&#x[0-9a-f]+;.")) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL")) {
                analysis.riskLevel = "HIGH";
            }
            analysis.reasons.add("Contains encoded characters (obfuscated/hidden URL)");
        }
        // Check for very long URLs (HIGH RISK) - often used in phishing
        if (url.length() > 100) {
            analysis.isSuspicious = true;
            if (!analysis.riskLevel.equals("CRITICAL")) {
                analysis.riskLevel = "HIGH";
            }
            analysis.reasons.add("Unusually long URL (often used to hide destination)");
        }
        // Check for domain typosquatting (HIGH RISK) - mimicking popular sites with slight differences
        String[] popularSites = {"google", "facebook", "apple", "microsoft", "amazon", "paypal", 
                                 "linkedin", "instagram", "twitter", "youtube", "netflix"};
        for (String site : popularSites) {
            if (lower.contains(site)) {
                // Check for slight variations like googlel, googl-e, g00gle, etc.
                if (lower.matches("." + site + "(l|l-e|0|0-e|e|e|1).")) {
                    analysis.isSuspicious = true;
                    if (!analysis.riskLevel.equals("CRITICAL")) {
                        analysis.riskLevel = "HIGH";
                    }
                    analysis.reasons.add("Possible domain typosquatting - mimics " + site);
                    break;
                }
            }
        }
        // Check for subdomain redirect patterns (MEDIUM RISK)
        if (lower.contains(".") && lower.split("\\.").length > 3) {
            String[] parts = lower.split("\\.");
            if (parts.length > 3 && (parts[0].contains("login") || parts[0].contains("admin") || 
                parts[0].contains("secure") || parts[0].contains("verify"))) {
                analysis.isSuspicious = true;
                if (!analysis.riskLevel.equals("CRITICAL") && !analysis.riskLevel.equals("HIGH")) {
                    analysis.riskLevel = "MEDIUM";
                }
                analysis.reasons.add("Suspicious subdomain structure (may be fake login redirect)");
            }
        }
        return analysis;  // Return the completed analysis
    }
    // Convenience method to check if a URL is suspicious
    private boolean isSuspiciousURL(String url) {
        return analyzeURL(url).isSuspicious;
    }

    // Show a dialog summarizing URL risk levels found in a ScanResult
    private void showURLWarnings(ScanResult result) {
        if (result == null || result.matches.isEmpty()) return;
        List<String> high = new ArrayList<>();
        List<String> med = new ArrayList<>();
        List<String> low = new ArrayList<>();
        for (Match m : result.matches) {
            if (m.urlAnalysis == null) continue;
            switch (m.urlAnalysis.riskLevel) {
                case "HIGH": high.add(m.text); break;
                case "MEDIUM": med.add(m.text); break;
                case "LOW": low.add(m.text); break;
                default: break;
            }
        }
        if (high.isEmpty() && med.isEmpty() && low.isEmpty()) return; // nothing to warn

        StringBuilder sb = new StringBuilder();
        if (!high.isEmpty()) {
            sb.append("High risk URLs detected:\n");
            for (String u : high) sb.append(" - ").append(u).append("\n");
            sb.append("\n");
        }
        if (!med.isEmpty()) {
            sb.append("Medium risk URLs detected:\n");
            for (String u : med) sb.append(" - ").append(u).append("\n");
            sb.append("\n");
        }
        if (!low.isEmpty()) {
            sb.append("Low risk URLs detected:\n");
            for (String u : low) sb.append(" - ").append(u).append("\n");
            sb.append("\n");
        }

        String title = !high.isEmpty() ? "High Risk URL(s) Detected" : (!med.isEmpty() ? "Medium Risk URL(s) Detected" : "Low Risk URL(s) Detected");
        int msgType = (!high.isEmpty() || !med.isEmpty()) ? JOptionPane.WARNING_MESSAGE : JOptionPane.INFORMATION_MESSAGE;
        JOptionPane.showMessageDialog(this, sb.toString(), title, msgType);
    }

    // Show a dialog summarizing the overall message risk (based on ScanResult)
    private void showMessageWarnings(ScanResult result) {
        if (result == null || result.riskLevel == null) return;
        String rl = result.riskLevel.toUpperCase();
        if (rl.contains("CRITICAL") || rl.contains("HIGH")) {
            JOptionPane.showMessageDialog(this,
                "High message risk detected:\n" + result.riskLevel + "\n\n" + result.recommendation,
                "High Risk Message",
                JOptionPane.WARNING_MESSAGE);
        } else if (rl.contains("MEDIUM")) {
            JOptionPane.showMessageDialog(this,
                "Medium message risk detected:\n" + result.riskLevel + "\n\n" + result.recommendation,
                "Medium Risk Message",
                JOptionPane.WARNING_MESSAGE);
        } else if (rl.contains("LOW")) {
            JOptionPane.showMessageDialog(this,
                "Low message risk detected:\n" + result.riskLevel + "\n\n" + result.recommendation,
                "Low Risk Message",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    // ========== SORTING TECHNIQUES - MERGE SORT IMPLEMENTATION ==========
    // This section implements merge sort algorithm for sorting detected scam patterns
    // ========== APPLY SORTING LOGIC ==========
    // This method applies the selected sorting option to the current scan results
    private void applySorting() {
        int sortIndex = sortComboBox.getSelectedIndex();  // Get selected sorting option
        // Choose sorting method based on selected option
        switch (sortIndex) {
            case 0: // Detection Order (no sorting needed)
                break;
            case 1: // Category A-Z (alphabetical ascending)
                mergeSort(currentResult.matches, 0, currentResult.matches.size() - 1, true);
                break;
            case 2: // Category Z-A (alphabetical descending)
                mergeSort(currentResult.matches, 0, currentResult.matches.size() - 1, false);
                break;
            case 3: // Match Length (Shortest First)
                mergeSortByLength(currentResult.matches, 0, currentResult.matches.size() - 1, true);
                break;
            case 4: // Match Length (Longest First)
                mergeSortByLength(currentResult.matches, 0, currentResult.matches.size() - 1, false);
                break;
        }
    }
    //CO-02 CONCEPT
    // ========== MERGE SORT BY CATEGORY ==========
    // Recursive merge sort that orders matches by category name
    private void mergeSort(List<Match> list, int left, int right, boolean ascending) {
        if (left < right) {
            int mid = (left + right) / 2;  // Calculate midpoint
            mergeSort(list, left, mid, ascending);  // Sort left half recursively
            mergeSort(list, mid + 1, right, ascending);  // Sort right half recursively
            mergeByCategory(list, left, mid, right, ascending);  // Merge the two sorted halves
        }
    }
    // ========== MERGE BY CATEGORY NAME ==========
    // This method merges two sorted sublists based on category names
    private void mergeByCategory(List<Match> list, int left, int mid, int right, boolean ascending)//merges two sorted sublists based on category names 
    {
        List<Match> temp = new ArrayList<>();//creates a temporary list to hold merged results
        int i = left, j = mid + 1;//pointers for the two sublists
        // Compare and merge the two sorted sublists by category
        while (i <= mid && j <= right) {
            int comparison = list.get(i).category.compareToIgnoreCase(list.get(j).category);//compares category names ignoring case
            if (ascending ? comparison <= 0 : comparison >= 0) {//decides order based on ascending/descending flag 
                temp.add(list.get(i++));//adds the match from the left sublist
            } else {
                temp.add(list.get(j++));//adds the match from the right sublist
            }
        }
        // Add remaining elements from left sublist
        while (i <= mid) temp.add(list.get(i++));//adds remaining matches from the left sublist
        // Add remaining elements from right sublist
        while (j <= right) temp.add(list.get(j++));//adds remaining matches from the right sublist
        
        // Copy merged results back to original list
        for (int k = 0; k < temp.size(); k++) {
            list.set(left + k, temp.get(k));//copies merged results back to the original list
        }
    }
    // ========== MERGE SORT BY MATCH LENGTH ==========
    // Recursive merge sort that orders matches by the length of detected text
    //CO-06 CONCEPT
    private void mergeSortByLength(List<Match> list, int left, int right, boolean ascending)//sorts matches by the length of matched text  
    {
        if (left < right) {
            int mid = (left + right) / 2;  // Calculate midpoint
            mergeSortByLength(list, left, mid, ascending);  // Sort left half recursively
            mergeSortByLength(list, mid + 1, right, ascending);  // Sort right half recursively
            mergeByLength(list, left, mid, right, ascending);  // Merge the two sorted halves
        }
    }
    // ========== MERGE BY TEXT LENGTH ==========
    // This method merges two sorted sublists based on the length of matched text
    private void mergeByLength(List<Match> list, int left, int mid, int right, boolean ascending)//merges two sorted sublists based on the length of matched text  
    {
        List<Match> temp = new ArrayList<>();//C0-6 CONCEPT//creates a temporary list to hold merged results
        int i = left, j = mid + 1;  // Pointers for left and right sublists
        // Compare and merge the two sorted sublists
        while (i <= mid && j <= right) {
            int len1 = list.get(i).text.length();  // Get length of text from left sublist
            int len2 = list.get(j).text.length();  // Get length of text from right sublist
            if (ascending ? len1 <= len2 : len1 >= len2) {
                temp.add(list.get(i++));//adds the match from the left sublist
            } else {
                temp.add(list.get(j++));//adds the match from the right sublist
            }
        }
        while (i <= mid) temp.add(list.get(i++));//adds remaining matches from the left sublist
        while (j <= right) temp.add(list.get(j++));//adds remaining matches from the right sublist
        for (int k = 0; k < temp.size(); k++) {
            list.set(left + k, temp.get(k));//copies merged results back to the original list
        }
    }
    // ========== DISPLAY RESULTS ==========
    private void displayResults(ScanResult result) {
        riskLabel.setText(result.riskLevel);//updates the risk level label with the calculated risk level
        riskPanel.setBackground(result.riskColor);//changes the background color of the risk panel based on the risk level
        riskLabel.setForeground(result.riskColor == RISK_MEDIUM ? Color.BLACK : Color.WHITE);//adjusts text color for readability
        StringBuilder text = new StringBuilder();//uses StringBuilder for efficient string concatenation
        //CO-03 CONCEPT
        text.append(" DETECTED INDICATORS: ").append(result.matches.size()).append("\n");//appends the number of detected indicators to the results text
        text.append(repeatChar("-", 60)).append("\n\n");//appends a separator line
        if (result.matches.isEmpty()) {
            text.append("No scam patterns detected.\n\n");//appends a message if no scam patterns were detected
        } else {
            for (int i = 0; i < result.matches.size(); i++) {
                Match m = result.matches.get(i);//iterates through each detected match
                text.append(i + 1).append(". ").append(m.category).append("\n");//appends the category of the match
                text.append("   └─ Found: \"").append(m.text).append("\" (").append(m.text.length()).append(" chars)\n");//appends the matched text and its length
                
                // Display URL analysis details if available
                if (m.urlAnalysis != null) {
                    text.append("   └─ URL Risk: ").append(m.urlAnalysis.riskLevel).append("\n");//appends the risk level of the URL
                    if (!m.urlAnalysis.reasons.isEmpty()) {
                        for (String reason : m.urlAnalysis.reasons) {
                            text.append("       • ").append(reason).append("\n");//appends each reason for the URL's risk level
                        }
                    }
                }
                text.append("\n");
            }
        }
        text.append(repeatChar("=", 60)).append("\n");//appends a separator line
        text.append(" RECOMMENDATION:\n");//appends the recommendation header
        text.append(repeatChar("=", 60)).append("\n");//appends a separator line
        text.append(result.recommendation);//appends the recommendation based on the risk level
        
        resultArea.setText(text.toString());//updates the result area with the constructed results text
        resultArea.setCaretPosition(0);//scrolls to the top of the results area
    }
    // ========== CLEAR FUNCTION ==========
    // This method clears all input and output fields, resetting the GUI to initial state
    private void clearFields() {
        messageArea.setText("");//clears the input message area
        resultArea.setText("");//clears the results area
        riskLabel.setText("No scan performed yet");//resets the risk level label
        riskPanel.setBackground(new Color(50, 50, 60));//resets the background color of the risk panel
        riskLabel.setForeground(new Color(180, 180, 180));//resets the text color of the risk label
        currentResult = null;//resets the current scan result
        sortComboBox.setSelectedIndex(0);//resets the sorting option to default
    }
    // ========== REPEAT CHARACTER HELPER METHOD ==========
    // This method repeats a character/string a specified number of times
    // Used for compatibility with Java versions prior to Java 11 (which has String.repeat)
    private String repeatChar(String s, int count) {
        if (s == null) s = "";
        StringBuilder sb = new StringBuilder(count * Math.max(1, s.length()));
        for (int i = 0; i < count; i++) {
            sb.append(s);  // Append the string 'count' times
        }
        return sb.toString();  // Return the concatenated result
    }
    // ========== SCAN RESULT DATA CLASS ==========
    // This inner class stores the results of a single scam detection scan
    // It contains all detected matches, risk assessment, and recommendations
    class ScanResult {
        List<Match> matches = new ArrayList<>();//CO-06 CONCEPT - stores all detected scam indicators and URLs
        String riskLevel;  // Overall risk level (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
        String recommendation;  // User recommendation based on risk level
        Color riskColor;  // Color associated with the risk level for GUI display
        // Method to add a pattern match to the results
        void addMatch(String category, String text) {
            matches.add(new Match(category, text));
        } 
        // Method to add a URL match with detailed analysis to the results
        void addURLMatch(String category, String text, URLAnalysis urlAnalysis) {
            matches.add(new Match(category, text, urlAnalysis));//adds a match with URL analysis to the list of matches
        }  
        // ========== CALCULATE RISK METHOD ==========
        // This method calculates the overall risk level based on detected patterns and categories
        // Score: total number of pattern matches found
        // Categories: number of unique scam categories detected
        void calculateRisk(int score, int categories)//CO-04 CONCEPT - calculates overall scam risk
        //CO-01 CONCEPT
        {
            // CRITICAL RISK: 5+ indicators detected - definite scam
            if (score >= 5) {
                riskLevel = " CRITICAL - DEFINITE SCAM";
                recommendation = "DO NOT RESPOND! Delete immediately. Block sender. Report as spam.";
                riskColor = RISK_CRITICAL;  // Red color for critical risk
            } 
            // HIGH RISK: 3+ indicators or 4+ categories - likely scam
            else if (score >= 3 || categories >= CRITICAL_CATEGORIES) {
                riskLevel = " HIGH RISK - LIKELY SCAM";
                recommendation = "Very suspicious. Do not click links or provide information. Delete and block.";
                riskColor = RISK_HIGH;  // Orange color for high risk
            } 
            // MEDIUM RISK: 2+ indicators or 2+ categories - possible scam
            else if (score >= 2 || categories >= MEDIUM_CATEGORIES) {
                riskLevel = " MEDIUM RISK - POSSIBLE SCAM";
                recommendation = "Be very cautious. Verify sender through official channels before responding.";
                riskColor = RISK_MEDIUM;  // Yellow color for medium risk
            } 
            // LOW RISK: 1 indicator - suspicious but not conclusive
            else if (score >= 1) {
                riskLevel = " LOW RISK - SUSPICIOUS";
                recommendation = "Contains suspicious elements. Exercise caution.";
                riskColor = RISK_LOW;  // Blue color for low risk
            } 
            // SAFE: No indicators detected
            else {
                riskLevel = " NO SCAM DETECTED";
                recommendation = "No obvious scam patterns found. Still be cautious with unknown senders.";
                riskColor = RISK_SAFE;  // Green color for safe
            }
        }
    }
    // ========== MATCH DATA CLASS ==========
    // This inner class represents a single detected scam indicator or URL
    class Match {
        String category;  // Category of the match (e.g., "Urgency/Pressure", "Suspicious URL")
        String text;  // The actual matched text from the message
        URLAnalysis urlAnalysis;  // Optional: detailed analysis if this is a URL match
        // Constructor for non-URL matches
        Match(String category, String text) {
            this.category = category;
            this.text = text;
        }
        // Constructor for URL matches with analysis
        Match(String category, String text, URLAnalysis urlAnalysis) {
            this.category = category;
            this.text = text;
            this.urlAnalysis = urlAnalysis;  // Store the URL analysis details
        }
    }
    // ========== URL ANALYSIS DATA CLASS ==========
    // This inner class stores the detailed analysis results for a single URL
    class URLAnalysis {
        String url;  // The URL being analyzed
        boolean isSuspicious;  // Whether the URL is flagged as suspicious
        String riskLevel = "SAFE";  // Risk level of the URL (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
        List<String> reasons = new ArrayList<>();  // List of reasons why the URL is suspicious  
        // Constructor to initialize URL analysis
        URLAnalysis(String url) {
            this.url = url;  // Store the URL
            this.isSuspicious = false;  // Default to safe unless flagged during analysis
        }
    }
    // ========== MAIN METHOD ==========
    // Entry point for the application - creates and displays the GUI window
    public static void main(String[] args) {
        // SwingUtilities.invokeLater ensures GUI operations run on the Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            ScamDetectorGUI gui = new ScamDetectorGUI();  // Create the main GUI frame
            gui.setVisible(true);  // Display the window to the user
        });
    }
}