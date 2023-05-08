#!/usr/bin/env python

import argparse
import json
import pandas as pd


def create_badge(cve: str, severity: str, BADGE_URL: str = "https://img.shields.io/static/v1?label={0}&message={1}&color={2}&style=flat") -> str:
    """
    Returns the URL of a static shields.io badge for a given vulnerability.

    Parameters:
        cve (str): The CVE identifier for the vulnerability.
        severity (str): The severity of the vulnerability, must be one of "critical", "high", "medium", "low", "none", or "unknown".
        BADGE_URL (str, optional): The URL pattern for the badge image. Defaults to "https://img.shields.io/static/v1?label={0}&message={1}&color={2}&style=flat".

    Returns:
        str: The URL of the generated badge.

    Raises:
        ValueError: If the severity is not one of the allowed values.
    """
    if severity == "critical":
        return BADGE_URL.format(cve, "critical", "red")

    elif severity == "high":
        return BADGE_URL.format(cve, "high", "orange")

    elif severity == "medium":
        return BADGE_URL.format(cve, "medium", "brightgreen")

    elif severity == "low":
        return BADGE_URL.format(cve, "low", "blue")

    elif severity == "none":
        return BADGE_URL.format(cve, "none", "lightgrey")

    elif severity == "unknown":
        return BADGE_URL.format(cve, "unkown", "black")

    else:
        raise ValueError(f"Unknown severity: '{severity}'")


def main(input_file, output_file):
    """
    Reads vulnerability data from a JSON file produced by `jake ddt`, processes it, and generates an issue body in Markdown format.

    Args:
        input_file (str): The path to the JSON file containing the vulnerability data produced by `jake ddt`.
        output_file (str): The path to the Markdown file where the issue body will be written.

    Returns:
        None.
    """
    with open(input_file, "r") as f:
        data = json.load(f)

    comps_by_ref = {}
    for comp in data.get("components"):
        comps_by_ref.update({comp.get("bom-ref"): {"name": comp.get("name"), "version": comp.get("version"),},})

    vulns_list = []
    for vuln in data.get("vulnerabilities"):
        vulns_list.append({"cve": vuln.get("bom-ref"),
                        "ref": [v.get("ref") for v in vuln.get("affects")],
                        "detail": vuln.get("detail"),
                        "severity": vuln.get("ratings")[0].get("severity"),
                        "url": vuln.get("source").get("url"), 
                        })

    vulns = pd.DataFrame.from_records(vulns_list)
    vulns = vulns.explode("ref").set_index("ref")
    vulns = vulns.loc[~vulns["detail"].str.startswith("**")]
    vulns["vulnerability"] = vulns.apply(lambda row: f"[![{row['cve']}]({create_badge(row['cve'], row['severity'])})]({row['url']})", axis=1)

    comps = pd.DataFrame().from_dict(comps_by_ref).T
    comps.index.name = "ref"

    table = comps.join(vulns, how="inner").reset_index(drop=True).groupby(["name", "version", "severity"]).agg(lambda x: " ".join(x))
    table = table.reset_index()
    table = table[["name", "version", "vulnerability"]]

    table["name"] = table["name"].apply(lambda x: f"`{x}`")
    table["version"] = table["version"].apply(lambda x: f"_{x}_")
    table.columns = table.columns.map(mapper={"name": "Package", "version": "Version", "vulnerability": "Vulnerability"})

    message = "## Vulnerability Report\n\n  _This is an automated issue opened by the Conda dependency checker workflow._\n\n<br>\n\n"
    body = message + table.reset_index(drop=True).to_markdown(index=False)

    with open(output_file, "w") as f:
        f.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="report")
    parser.add_argument("-i", "--infile", help="input JSON file")
    parser.add_argument("-o", "--outfile", help="output Markdown file")
    args = parser.parse_args()

    main(args.infile, args.outfile)
