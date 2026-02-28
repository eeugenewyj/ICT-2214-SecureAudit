"""
Generate synthetic PHP vulnerability dataset for training
Aligned with 64 patterns from pattern_registry.py
"""
import json
import random
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pattern_registry import PATTERNS


class VulnerableCodeGenerator:
    """Generate realistic vulnerable and safe PHP code samples"""
    
    def __init__(self):
        self.patterns = PATTERNS
        self.vulnerability_types = list(set([p.vuln_type for p in PATTERNS]))
    
    def generate_vulnerable_sql_injection(self):
        """Generate SQL injection vulnerable code"""
        templates = [
            """<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
mysql_query($query);
?>""",
            """<?php
$username = $_POST['username'];
$sql = "SELECT * FROM accounts WHERE username = '$username'";
mysqli_query($conn, $sql);
?>""",
            """<?php
$table = $_GET['table'];
$query = "SELECT * FROM " . $table;
$result = mysqli_query($conn, $query);
?>""",
            """<?php
$order = $_GET['order'];
$sql = "SELECT * FROM products ORDER BY " . $order;
mysqli_query($conn, $sql);
?>""",
            """<?php
$id = $_REQUEST['id'];
$pdo->query("DELETE FROM users WHERE id = " . $id);
?>""",
            """<?php
$name = $_POST['name'];
$sql = "INSERT INTO users (name) VALUES ('$name')";
mysql_query($sql);
?>""",
            """<?php
$status = $_GET['status'];
$query = "UPDATE orders SET status = '$status' WHERE id = 1";
mysqli_query($conn, $query);
?>""",
            """<?php
$ids = $_GET['ids'];
mysqli_multi_query($conn, "SELECT * FROM users WHERE id IN ($ids)");
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_xss(self):
        """Generate XSS vulnerable code"""
        templates = [
            """<?php
echo $_GET['name'];
?>""",
            """<?php
print $_POST['comment'];
?>""",
            """<?php
$message = $_GET['msg'];
echo "<div>$message</div>";
?>""",
            """<?php
printf("Hello %s", $_GET['user']);
?>""",
            """<?php
$url = $_GET['redirect'];
echo "<a href='$url'>Click here</a>";
?>""",
            """<?php
$style = $_GET['color'];
echo "<div style='color: $style'>Text</div>";
?>""",
            """<?php
$handler = $_GET['onclick'];
echo "<button onclick='$handler'>Click</button>";
?>""",
            """<script>
var data = <?php echo $_GET['data']; ?>;
</script>""",
            """<?php
$html = $_POST['content'];
echo "<div class='content'>$html</div>";
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_command_injection(self):
        """Generate command injection vulnerable code"""
        templates = [
            """<?php
eval($_GET['code']);
?>""",
            """<?php
$cmd = $_GET['command'];
exec($cmd);
?>""",
            """<?php
system($_POST['cmd']);
?>""",
            """<?php
$file = $_GET['file'];
shell_exec("cat " . $file);
?>""",
            """<?php
passthru($_REQUEST['command']);
?>""",
            """<?php
$dir = $_GET['dir'];
`ls $dir`;
?>""",
            """<?php
popen($_POST['cmd'], 'r');
?>""",
            """<?php
proc_open($_GET['program'], [], $pipes);
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_file_inclusion(self):
        """Generate file inclusion vulnerable code"""
        templates = [
            """<?php
include($_GET['page']);
?>""",
            """<?php
require($_POST['file']);
?>""",
            """<?php
include_once($_GET['module']);
?>""",
            """<?php
require_once($_COOKIE['template']);
?>""",
            """<?php
$file = $_GET['file'];
$content = file_get_contents($file);
?>""",
            """<?php
fopen($_POST['filename'], 'r');
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_path_traversal(self):
        """Generate path traversal vulnerable code"""
        templates = [
            """<?php
$file = $_GET['file'];
readfile($file);
?>""",
            """<?php
$path = $_POST['path'];
unlink($path);
?>""",
            """<?php
$file = "uploads/" . $_GET['file'];
include($file);
?>""",
            """<?php
$src = $_GET['source'];
$dst = $_POST['dest'];
copy($src, $dst);
?>""",
            """<?php
rename($_GET['old'], $_GET['new']);
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_deserialization(self):
        """Generate deserialization vulnerable code"""
        templates = [
            """<?php
$data = $_GET['data'];
unserialize($data);
?>""",
            """<?php
$obj = unserialize($_COOKIE['user']);
?>""",
            """<?php
$file = "phar://uploads/" . $_GET['file'];
file_get_contents($file);
?>""",
            """<?php
$yaml = $_POST['config'];
yaml_parse($yaml);
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_auth(self):
        """Generate authentication vulnerabilities"""
        templates = [
            """<?php
session_id($_GET['session']);
session_start();
?>""",
            """<?php
$password = "admin123";
$user = "admin";
?>""",
            """<?php
session_start();
$_SESSION['user'] = $_POST['username'];
?>""",
            """<?php
$password = $_POST['password'];
$hash = md5($password);
?>""",
            """<?php
$pwd = $_POST['pwd'];
$hash = sha1($pwd);
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_csrf(self):
        """Generate CSRF vulnerable code"""
        templates = [
            """<?php
if ($_GET['delete']) {
    $sql = "DELETE FROM users WHERE id = " . $_GET['id'];
    mysqli_query($conn, $sql);
}
?>""",
            """<?php
if ($_POST['submit']) {
    // Process form without CSRF token
    update_user($_POST['data']);
}
?>""",
            """<form method="post" action="update.php">
    <input name="email" value="">
    <button type="submit">Update</button>
</form>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_info_disclosure(self):
        """Generate information disclosure vulnerabilities"""
        templates = [
            """<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
?>""",
            """<?php
phpinfo();
?>""",
            """<?php
var_dump($_SERVER);
?>""",
            """<?php
print_r($_SESSION);
?>""",
        ]
        return random.choice(templates)
    
    def generate_vulnerable_xxe(self):
        """Generate XXE vulnerable code"""
        templates = [
            """<?php
$xml = $_POST['xml'];
simplexml_load_string($xml);
?>""",
            """<?php
$doc = new DOMDocument();
$doc->loadXML($_GET['data']);
?>""",
        ]
        return random.choice(templates)
    
    def generate_safe_code(self):
        """Generate safe PHP code examples"""
        templates = [
            """<?php
$id = intval($_GET['id']);
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
?>""",
            """<?php
$name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');
echo $name;
?>""",
            """<?php
$password = $_POST['password'];
$hash = password_hash($password, PASSWORD_ARGON2ID);
?>""",
            """<?php
$allowed_files = ['header.php', 'footer.php'];
$file = $_GET['file'];
if (in_array($file, $allowed_files)) {
    include($file);
}
?>""",
            """<?php
session_start();
if ($_POST['csrf_token'] === $_SESSION['csrf_token']) {
    // Process form
}
?>""",
            """<?php
$stmt = $conn->prepare("INSERT INTO users (name, email) VALUES (?, ?)");
$stmt->bind_param("ss", $name, $email);
$stmt->execute();
?>""",
            """<?php
$file = basename($_GET['file']);
$allowed_dir = '/var/www/uploads/';
$path = realpath($allowed_dir . $file);
if (strpos($path, $allowed_dir) === 0) {
    readfile($path);
}
?>""",
            """<?php
$data = json_decode($_POST['data'], true);
// Safe: using JSON instead of unserialize
?>""",
            """<?php
// Production settings
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);
?>""",
            """<?php
$allowed_commands = ['list', 'info', 'help'];
$cmd = $_GET['cmd'];
if (in_array($cmd, $allowed_commands)) {
    // Execute safe predefined commands
}
?>""",
        # Add decoy patterns, safe code that LOOKS dangerous
            """<?php
$id = $_GET['id'];  // has $_GET but is safe
$id = intval($id);
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
?>""",
        # Vulnerable-looking variable names but safe logic
        """<?php
$sql_query = "SELECT * FROM users WHERE id = ?";
$stmt = $pdo->prepare($sql_query);
$stmt->execute([$safe_id]);
?>""",
        ]
        return random.choice(templates)
    
    def generate_sample(self, is_vulnerable):
        """Generate a single code sample"""
        if not is_vulnerable:
            return self.generate_safe_code(), 0
        
        # Choose random vulnerability type
        generators = {
            'sql_injection': self.generate_vulnerable_sql_injection,
            'xss': self.generate_vulnerable_xss,
            'command_injection': self.generate_vulnerable_command_injection,
            'file_inclusion': self.generate_vulnerable_file_inclusion,
            'path_traversal': self.generate_vulnerable_path_traversal,
            'deserialization': self.generate_vulnerable_deserialization,
            'weak_auth': self.generate_vulnerable_auth,
            'csrf': self.generate_vulnerable_csrf,
            'info_disclosure': self.generate_vulnerable_info_disclosure,
            'xxe': self.generate_vulnerable_xxe,
        }
        
        vuln_type = random.choice(list(generators.keys()))
        code = generators[vuln_type]()
        
        return code, 1
    
    def generate_dataset(self, num_samples=1000, train_ratio=0.8):
        """
        Generate complete dataset
        
        Args:
            num_samples: Total number of samples to generate
            train_ratio: Ratio of training samples (rest will be test)
        
        Returns:
            dict: Dataset with train and test splits
        """
        print(f"Generating {num_samples} code samples...")
        print(f"Train/Test split: {train_ratio:.0%}/{1-train_ratio:.0%}")
        
        samples = []
        
        # Generate balanced dataset (50% vulnerable, 50% safe)
        num_vulnerable = num_samples // 2
        num_safe = num_samples - num_vulnerable
        
        print(f"\nGenerating {num_vulnerable} vulnerable samples...")
        for i in range(num_vulnerable):
            code, label = self.generate_sample(is_vulnerable=True)
            samples.append({
                "code": code,
                "label": label,
                "type": "vulnerable"
            })
            if (i + 1) % 100 == 0:
                print(f"  Generated {i + 1}/{num_vulnerable} vulnerable samples")
        
        print(f"\nGenerating {num_safe} safe samples...")
        for i in range(num_safe):
            code, label = self.generate_sample(is_vulnerable=False)
            samples.append({
                "code": code,
                "label": label,
                "type": "safe"
            })
            if (i + 1) % 100 == 0:
                print(f"  Generated {i + 1}/{num_safe} safe samples")
        
        # Shuffle samples
        random.shuffle(samples)
        
        # Split into train and test
        split_idx = int(len(samples) * train_ratio)
        train_samples = samples[:split_idx]
        test_samples = samples[split_idx:]
        
        dataset = {
            "metadata": {
                "total_samples": len(samples),
                "train_samples": len(train_samples),
                "test_samples": len(test_samples),
                "num_patterns": len(self.patterns),
                "vulnerability_types": self.vulnerability_types
            },
            "train": train_samples,
            "test": test_samples
        }
        
        print(f"\n Dataset generation complete!")
        print(f"   Total samples: {len(samples)}")
        print(f"   Training samples: {len(train_samples)}")
        print(f"   Test samples: {len(test_samples)}")
        print(f"   Patterns used: {len(self.patterns)}")
        
        return dataset


def main():
    """Main function to generate and save dataset"""
    
    # Create generator
    generator = VulnerableCodeGenerator()
    
    # Generate dataset
    dataset = generator.generate_dataset(
        num_samples=2000,  # Adjust this number as needed
        train_ratio=0.8
    )
    
    # Save to file
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = os.path.join(output_dir, 'vulnerability_dataset.json')
    
    print(f"\nSaving dataset to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f" Dataset saved successfully!")
    print(f"\nDataset statistics:")
    print(f"  File: {output_file}")
    print(f"  Size: {os.path.getsize(output_file) / 1024:.2f} KB")
    print(f"  Total samples: {dataset['metadata']['total_samples']}")
    print(f"  Train samples: {dataset['metadata']['train_samples']}")
    print(f"  Test samples: {dataset['metadata']['test_samples']}")
    print(f"\nNext step: Run 'python train_model.py' to train the model")


if __name__ == "__main__":
    main()