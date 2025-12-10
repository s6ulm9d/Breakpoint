def generate_html_report(results, output_path, target):
    secure = sum(1 for r in results if r.status == "SECURE")
    vuln = sum(1 for r in results if r.status == "VULNERABLE")
    inconclusive = sum(1 for r in results if r.status == "INCONCLUSIVE")
    error = sum(1 for r in results if r.status == "ERROR")
    
    # Calculate Score (only Secure vs Vulnerable counts)
    denom = secure + vuln
    score = (secure / denom * 100) if denom > 0 else 0
    
    rows = ""
    for r in results:
        color = "green" if r.status == "SECURE" else "red" if r.status == "VULNERABLE" else "gray"
        rows += f"""
        <tr style="border-bottom: 1px solid #ddd;">
            <td style="padding: 10px;">{r.id}</td>
            <td style="padding: 10px;">{r.type}</td>
            <td style="padding: 10px; color: {color}; font-weight: bold;">{r.status}</td>
            <td style="padding: 10px;">{r.severity or '-'}</td>
            <td style="padding: 10px;">{r.details}</td>
        </tr>
        """
        
    html = f"""
    <html>
    <head><title>BREAKPOINT Report</title></head>
    <body style="font-family: sans-serif; padding: 20px;">
        <h1>BREAKPOINT Security Report</h1>
        <h3>Target: {target}</h3>
        <div style="background: #f0f0f0; padding: 15px; border-radius: 5px;">
            <h2>Resilience Score: {score:.1f}%</h2>
            <p>Secure: {secure} | Vulnerable: {vuln} | Inconclusive: {inconclusive} | Error: {error}</p>
        </div>
        <br>
        <table style="width: 100%; border-collapse: collapse; text-align: left;">
            <thead style="background: #333; color: white;">
                <tr>
                    <th style="padding: 10px;">ID</th>
                    <th style="padding: 10px;">Type</th>
                    <th style="padding: 10px;">Status</th>
                    <th style="padding: 10px;">Severity</th>
                    <th style="padding: 10px;">Details</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </body>
    </html>
    """
    
    with open(output_path, "w") as f:
        f.write(html)
    print(f"[*] HTML Report generated at {output_path}")
