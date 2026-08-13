"""
Import Script for MITRE ATT&CK Enterprise STIX JSON Dataset.

Usage:
  python scripts/import_mitre_attack.py --stix path/to/enterprise-attack.json
"""
import argparse
import logging
import sys

from manager.mitre.mitre_mapper import MitreDataImporter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Import MITRE ATT&CK STIX bundle into database.")
    parser.add_argument("--stix", required=True, help="Path to STIX JSON file.")
    args = parser.parse_args()

    importer = MitreDataImporter()
    tactics, techniques = importer.parse_stix_bundle(args.stix)

    logger.info(f"Successfully parsed {len(tactics)} tactics and {len(techniques)} techniques.")
    # In full environment, tactics and techniques are written to PostgreSQL via SQLAlchemy session.


if __name__ == "__main__":
    main()
