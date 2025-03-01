import os
from analyzer import analyze_email

def read_email_from_file(file_path):
    """
    Reads the email content from a given file path.

    Parameters:
        file_path (str): Path to the email file.

    Returns:
        str: Email content as a string, or None if an error occurs.
    """
    if not os.path.exists(file_path):
        print("❌ Error: File not found. Please check the file path.")
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read().strip()  # Read and remove any trailing spaces/newlines
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return None

def main():
    """
    Main function to handle user input and analyze phishing emails.
    """
    print("\n🔍 **PhishShield - Phishing Email Analyzer** 🔍")
    print("===============================================")
    print("Choose an option to input the email:")
    print("1️⃣ Paste email content")
    print("2️⃣ Provide email file path")
    
    choice = input("\nEnter your choice (1 or 2): ").strip()

    if choice == "1":
        email_content = input("\n📩 Paste the email content:\n").strip()

    elif choice == "2":
        file_path = input("\n📁 Enter the email file path: ").strip()
        email_content = read_email_from_file(file_path)
        if email_content is None:
            return  # Stop execution if file reading fails

    else:
        print("\n❌ Invalid choice. Please enter 1 or 2.")
        return

    # ✅ Analyze the email content
    analysis_result = analyze_email(email_content)

    # 📊 **Display Results**
    print("\n📊 **Phishing Analysis Report**")
    print("===================================")
    print(f"🔢 **Phishing Score:** {analysis_result['score']} / 100")
    print(f"⚠️ **Risk Level:** {analysis_result['risk_level']}\n")

    print("📝 **Reasons for Detection:**")
    if analysis_result["reasons"]:
        for reason in analysis_result["reasons"]:
            print(f"   - {reason}")
    else:
        print("   ✅ No suspicious indicators detected.")

    print("\n✅ **Analysis Completed! Stay Safe Online.** 🛡️\n")

if __name__ == "__main__":
    main()

