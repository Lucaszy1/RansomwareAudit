import csv
import html as html_lib
import json

def generate_json_report(target_dir, file_reports, behavior_data, risk_summary):
    from datetime import datetime
    
    report = {
        "target_directory": target_dir,
        "timestamp": datetime.now().isoformat(),
        "risk_summary": risk_summary,
        "behavior_analysis": behavior_data,
        "file_reports": file_reports,
        "statistics": {
            "total_files_scanned": len(file_reports),
            "high_risk_file_count": risk_summary.get('flagged_count', len(risk_summary.get('flagged_files', []))),
            "suspicious_extension_count": len(behavior_data.get('suspicious_extensions', []))
        }
    }
    
    return report

def save_report(report, path):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)

def save_csv_report(flagged_files, path):
    if not flagged_files:
        return
    
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['File', 'Entropy', 'Permissions', 'Risk Score'])
        
        for item in flagged_files:
            writer.writerow([
                item['file'],
                item.get('entropy', 'N/A'),
                item.get('permissions', 'N/A'),
                item['score']
            ])

def save_html_report(report, path):
    risk_summary = report["risk_summary"]
    total_score = risk_summary["total_score"]
    risk_level = risk_summary["risk_level"]
    
    if risk_level == "CRITICAL":
        risk_class = "critical"
    elif risk_level == "HIGH":
        risk_class = "high"
    elif risk_level == "MEDIUM":
        risk_class = "medium"
    else:
        risk_class = "low"
    
    file_score = risk_summary.get("top_file_score", 0)
    behavior_score = risk_summary.get("behavior_score", 0)
    
    ext_count = {}
    for file_info in report.get("file_reports", []):
        ext = file_info.get("extension", "unknown")
        ext_count[ext] = ext_count.get(ext, 0) + 1
    
    # escape "<" so a crafted extension can't close the <script> tag
    ext_labels = json.dumps(list(ext_count.keys())).replace("<", "\\u003c")
    ext_counts = json.dumps(list(ext_count.values()))
    
    flagged_rows = ""
    for item in risk_summary.get("flagged_files", [])[:20]:
        flagged_rows += f"""
        <tr>
            <td>{html_lib.escape(item['file'])}</td>
            <td>{html_lib.escape("; ".join(item.get('reasons', [])))}</td>
            <td>{html_lib.escape(item.get('level', ''))}</td>
            <td>{item['score']}</td>
        </tr>
        """
    
    if not flagged_rows:
        flagged_rows = "<tr><td colspan='4' style='text-align:center; color:#27ae60;'>No high-risk files found</td></tr>"
    
    behavior_reasons = report.get("risk_summary", {}).get("behavior_reasons", [])
    if behavior_reasons:
        behavior_section = "<h3>Risk Factors Detected</h3><ul>"
        for reason in behavior_reasons[:5]:
            behavior_section += f"<li>{html_lib.escape(reason)}</li>"
        behavior_section += "</ul>"
    else:
        behavior_section = "<p style='color:#27ae60;'>No suspicious behavioral patterns detected</p>"
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ransomware Risk Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1.5em;
            font-weight: bold;
            margin-top: 20px;
        }}
        .risk-badge.low {{
            background: #27ae60;
        }}
        .risk-badge.medium {{
            background: #f39c12;
        }}
        .risk-badge.high {{
            background: #e74c3c;
        }}
        .risk-badge.critical {{
            background: #c0392b;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        .content {{
            padding: 40px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border-left: 5px solid #667eea;
        }}
        .stat-card h3 {{
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .section {{
            margin: 40px 0;
        }}
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Ransomware Risk Assessment</h1>
            <p>Target: {html_lib.escape(str(report["target_directory"]))}</p>
            <p>Scan Date: {report["timestamp"]}</p>
            <div class="risk-badge {risk_class}">{risk_level}</div>
        </div>
        
        <div class="content">
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Risk Score</h3>
                    <div class="number">{total_score:.1f}</div>
                </div>
                <div class="stat-card">
                    <h3>Files Scanned</h3>
                    <div class="number">{report["statistics"]["total_files_scanned"]}</div>
                </div>
                <div class="stat-card">
                    <h3>High-Risk Files</h3>
                    <div class="number">{report["statistics"]["high_risk_file_count"]}</div>
                </div>
                <div class="stat-card">
                    <h3>Behavior Score</h3>
                    <div class="number">{behavior_score}</div>
                </div>
            </div>

            <div class="section">
                <h2>Risk Breakdown</h2>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>

            <div class="section">
                <h2>File Extension Distribution</h2>
                <div class="chart-container">
                    <canvas id="extensionChart"></canvas>
                </div>
            </div>

            <div class="section">
                <h2>High-Risk Files</h2>
                <table>
                    <thead>
                        <tr>
                            <th>File Path</th>
                            <th>Reasons</th>
                            <th>Level</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {flagged_rows}
                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Behavioral Analysis</h2>
                {behavior_section}
            </div>
        </div>
    </div>

    <script>
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['File Risk', 'Behavior Risk'],
                datasets: [{{
                    data: [{file_score}, {behavior_score}],
                    backgroundColor: ['#3498db', '#e74c3c']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});

        const extCtx = document.getElementById('extensionChart').getContext('2d');
        new Chart(extCtx, {{
            type: 'bar',
            data: {{
                labels: {ext_labels},
                datasets: [{{
                    label: 'File Count',
                    data: {ext_counts},
                    backgroundColor: '#667eea'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)

    print(f"\n[+] HTML DASHBOARD CREATED: {path}")
    print("    Open this file in your browser now!\n")
