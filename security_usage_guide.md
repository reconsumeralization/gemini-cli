# 🔒 Gemini CLI Enhanced Security System - Usage Guide

## Quick Start

### 1. **Set Your Security Profile**
```bash
# For beginners (maximum safety)
node security_cli.js set beginner

# For regular users (recommended)
node security_cli.js set standard

# For developers (more permissive)
node security_cli.js set developer
```

### 2. **Use YOLO Mode Safely**
```bash
# Safe commands execute automatically
gemini-cli --yolo "echo 'Hello World'"   # ✅ Executes immediately

# Medium-risk commands show warnings
gemini-cli --yolo "cp file1 file2"       # ⚠️ Shows tip, then executes

# Dangerous commands are blocked with education
gemini-cli --yolo "rm -rf /"            # ❌ Blocked with alternatives
```

### 3. **Monitor Your Security**
```bash
# View current security settings
node security_cli.js info

# Check security logs
node security_cli.js logs

# Test commands before using
node security_cli.js test "sudo rm -rf /var"
```

## Security Profiles Explained

### **Beginner Profile** 🛡️
- **Commands**: Only 6 safest commands (echo, ls, cat, pwd, whoami, date)
- **Risk Tolerance**: Zero tolerance for risk
- **Education**: Maximum guidance and explanations
- **Best For**: New users learning command line safely

### **Standard Profile** ⚖️
- **Commands**: 40+ safe commands including development tools
- **Risk Tolerance**: Low risk with helpful warnings
- **Education**: Balanced guidance with helpful tips
- **Best For**: Regular users (this is the default)

### **Advanced Profile** 🔧
- **Commands**: 50+ commands including system tools
- **Risk Tolerance**: Medium risk with some warnings
- **Education**: Minimal guidance, assumes knowledge
- **Best For**: Power users who know what they're doing

### **Developer Profile** 💻
- **Commands**: 55+ commands including containers and development tools
- **Risk Tolerance**: High risk with safety warnings
- **Education**: Contextual tips for development workflows
- **Best For**: Developers working on projects

## Common Usage Scenarios

### **Scenario 1: Safe File Operations**
```bash
# These work in all profiles
gemini-cli --yolo "ls -la"
gemini-cli --yolo "cat README.md"
gemini-cli --yolo "pwd"

# These require higher profiles
gemini-cli --yolo "find . -name '*.js'"     # Standard+ profiles
gemini-cli --yolo "git status"               # Standard+ profiles
```

### **Scenario 2: Development Workflow**
```bash
# Set developer profile for development work
node security_cli.js set developer

# Development commands now work
gemini-cli --yolo "npm install"
gemini-cli --yolo "git push origin main"
gemini-cli --yolo "docker build ."
gemini-cli --yolo "node server.js"
```

### **Scenario 3: Learning Command Line**
```bash
# Set beginner profile to learn safely
node security_cli.js set beginner

# Only safe commands work - perfect for learning
gemini-cli --yolo "ls"               # ✅ Works
gemini-cli --yolo "cat file.txt"     # ✅ Works
gemini-cli --yolo "rm file.txt"      # ❌ Blocked with explanation

# When blocked, get helpful alternatives
# "Use rm -i for interactive confirmation"
# "Use trash-cli for recoverable deletion"
```

## Troubleshooting

### **Command Blocked Unexpectedly**
```bash
# Test why a command is blocked
node security_cli.js test "your command here"

# Switch to a more permissive profile
node security_cli.js set developer
```

### **Need More Commands Available**
```bash
# Check current profile restrictions
node security_cli.js info

# Switch to advanced profile
node security_cli.js set advanced

# Or developer profile for full access
node security_cli.js set developer
```

### **Understanding Risk Levels**
- **LOW RISK**: Safe commands that execute automatically
- **MEDIUM RISK**: Commands with warnings that still execute
- **HIGH RISK**: Dangerous commands that are blocked

### **Reviewing Security Logs**
```bash
# View recent security activity
node security_cli.js logs

# Logs show:
# - Commands executed/blocked
# - Risk levels and reasons
# - User and session information
# - Timestamped audit trail
```

## Advanced Configuration

### **Custom Security Policies**
The system is designed to be extensible. You can:

1. **Modify command allowlists** for your organization
2. **Add custom dangerous command patterns**
3. **Create organization-specific profiles**
4. **Integrate with existing security systems**

### **Integration with CI/CD**
```bash
# Use standard profile for automated builds
node security_cli.js set standard

# Use developer profile for development
node security_cli.js set developer
```

## Best Practices

### **1. Choose the Right Profile**
- **Start with Standard** for most users
- **Use Beginner** when learning or with new team members
- **Use Developer** for development work
- **Use Advanced** only when you know what you're doing

### **2. Test Commands First**
```bash
# Always test potentially risky commands
node security_cli.js test "sudo docker run --privileged"
node security_cli.js test "rm -rf /tmp/cache"
```

### **3. Monitor Your Usage**
```bash
# Regularly check your security logs
node security_cli.js logs

# Review blocked commands to understand risks
# Look for patterns in medium-risk command usage
```

### **4. Educate Your Team**
```bash
# Show the security tutorial to new team members
node security_cli.js tutorial

# Use beginner profile for training sessions
node security_cli.js set beginner
```

## Security Guarantees

### **What the System Protects Against:**
- ✅ **Command Injection**: Shell metacharacter attacks
- ✅ **Arbitrary Code Execution**: Dangerous command execution
- ✅ **Privilege Escalation**: Sudo/su command blocking
- ✅ **System Destruction**: File system destruction prevention
- ✅ **Sensitive Data Exposure**: Environment variable filtering
- ✅ **Mount Path Traversal**: Unauthorized directory access

### **What the System Allows:**
- ✅ **Safe Automation**: Approved commands run automatically
- ✅ **Development Workflows**: Developer profile for coding
- ✅ **Learning Experience**: Educational feedback system
- ✅ **Customization**: Profile-based security levels
- ✅ **Monitoring**: Complete audit trail

## Getting Help

### **Built-in Help**
```bash
# Interactive security CLI help
node security_cli.js --help

# Security tutorial
node security_cli.js tutorial

# Current configuration
node security_cli.js info
```

### **Educational Resources**
- **Security Tutorial**: `node security_cli.js tutorial`
- **Command Testing**: `node security_cli.js test "command"`
- **Profile Information**: `node security_cli.js profiles`
- **Security Logs**: `node security_cli.js logs`

This enhanced security system transforms command-line usage from risky to safe while maintaining full automation capabilities. Choose your security profile, use YOLO mode confidently, and enjoy a safer command-line experience!
