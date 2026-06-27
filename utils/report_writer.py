from datetime import datetime

class ReportWriter:
    def write_markdown(self, module_name, target, findings, output_path):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# {module_name} Report",
            f"**Target:** `{target}`  ",
            f"**Date:** {ts}  ",
            f"**Findings:** {len(findings)}",
            "", "---", "",
        ]
        if not findings:
            lines.append("_No findings._")
        else:
            for i, f in enumerate(findings, 1):
                lines.append(f"## Finding {i}")
                for k, v in f.items():
                    lines.append(f"- **{k.capitalize()}:** {v}")
                lines.append("")
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
