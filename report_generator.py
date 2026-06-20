import os
from fpdf import FPDF


class ReportGenerator:

    def generate(self, title, sections):

        # Ensure folder exists
        os.makedirs("reports", exist_ok=True)

        pdf = FPDF()
        pdf.add_page()

        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, txt=title, ln=True, align="C")

        pdf.ln(5)

        # Content
        pdf.set_font("Arial", size=12)

        for section_title, content in sections.items():

            # Section header
            pdf.set_font("Arial", "B", 12)
            pdf.cell(200, 10, txt=section_title, ln=True)

            pdf.set_font("Arial", size=11)

            # Section body
            if isinstance(content, dict):
                for k, v in content.items():
                    pdf.cell(200, 8, txt=f"{k}: {v}", ln=True)
            elif isinstance(content, list):
                for item in content:
                    pdf.cell(200, 8, txt=str(item), ln=True)
            else:
                pdf.cell(200, 8, txt=str(content), ln=True)

            pdf.ln(3)

        path = "reports/cyber_report.pdf"
        pdf.output(path)

        return path