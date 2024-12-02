import json
def generate_markdown(data):
    md = f"# {data['title']}\n\n"
    md += f"{data['description']}\n\n"
    
    md += "## Features 🚀\n\n"
    for feature in data['features']:
        md += f"- {feature}\n"
    md += "\n"
    
    md += "## Installation 💻\n\n\n"
    for step in data['installation']['steps']:
        md += f"{step}\n"
    md += "\n\n"
    
    md += "## Usage 🔧\n\n"
    md += "Launch the GUI interface:\n\n"
    md += f"{data['usage']['gui']}\n\n\n"
    md += "Run specific modules:\n\n"
    for module in data['usage']['modules']:
        md += f"{module}\n"
    md += "\n\n"
    
    md += "## Requirements 📋\n\n"
    for req in data['requirements']:
        md += f"- {req}\n"
    md += "\n"
    
    md += "## Contributing 🤝\n\n"
    for step in data['contributing']:
        md += f"{step}\n"
    md += "\n"
    
    md += f"## License 📄\n\nThis project is licensed under the {data['license']} License.\n\n"
    md += f"## Disclaimer ⚠️\n\n{data['disclaimer']}\n\n"
    
    md += "## Contact 📧\n\n"
    for key, value in data['contact'].items():
        md += f"- {key.capitalize()}: {value}\n"
    md += "\n"
    
    md += "## Acknowledgments 🌟\n\n"
    for ack in data['acknowledgments']:
        md += f"- {ack}\n"
    
    return md

# Usage
with open('readme_template.json', 'r') as f:
    data = json.load(f)

markdown = generate_markdown(data)
with open('README.md', 'w') as f:
    f.write(markdown)
