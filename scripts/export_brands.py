import csv
import os
import sys
from sqlalchemy import create_engine, Column, Integer, String, func, TIMESTAMP
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import NoResultFound, MultipleResultsFound, SQLAlchemyError
from urllib.parse import quote
# --- SQLAlchemy Setup ---
# !!! IMPORTANT: Replace with your actual database connection URL !!!
# Format: "mysql+pymysql://user:password@host:port/database_name"
# Make sure you have installed the appropriate driver (e.g., PyMySQL or mysqlclient)
encoded_password = quote('rathod_23')
DATABASE_URL = "mysql+pymysql://root:" + encoded_password + "@localhost:3307/test" # CHANGE THIS

try:
    engine = create_engine(DATABASE_URL, echo=False) # Set echo=True for debugging SQL
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
except ImportError as e:
     print(f"Error: SQLAlchemy or DB driver not installed? {e}")
     print("Please run: pip install SQLAlchemy \"PyMySQL\" (or mysqlclient)")
     sys.exit(1)
except Exception as e:
    print(f"Error creating SQLAlchemy engine: {e}")
    print(f"Check your DATABASE_URL: {DATABASE_URL}")
    sys.exit(1)


# --- Define your Brand model ---
# !!! IMPORTANT: Adjust class name, table name, and columns to match your DB !!!
class Brand(Base):
    __tablename__ = 'brands' # CHANGE if your table name is different

    id = Column(Integer, primary_key=True, index=True) # Assuming an integer PK
    name = Column(String(255), unique=True, index=True, nullable=False) # Adjust String length if needed
    image = Column(String(512), nullable=True) # Adjust String length if needed
    # Add other columns if necessary for your model context
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now(), nullable=False)

# You might want to create the table if it doesn't exist,
# but typically this is handled by migrations (e.g., Alembic) in FastAPI projects.
# Base.metadata.create_all(bind=engine) # Uncomment only if you need the script to create the table

# --- End SQLAlchemy Setup ---


def update_brands_from_csv(db_session, csv_filepath):
    """
    Reads a CSV file and updates the 'image' field for existing Brand records
    in the database using SQLAlchemy based on the brand name.

    Args:
        db_session: The SQLAlchemy session instance.
        csv_filepath (str): The path to the CSV file.
                          Expected columns: 'name', 'image'.
    """
    if not os.path.exists(csv_filepath):
        print(f"Error: CSV file not found at {csv_filepath}")
        return

    try:
        with open(csv_filepath, mode='r', encoding='utf-8-sig') as csvfile: # Use utf-8-sig to handle potential BOM
            try:
                dialect = csv.Sniffer().sniff(csvfile.read(1024))
                csvfile.seek(0)
                reader = csv.DictReader(csvfile, dialect=dialect)
            except csv.Error:
                print("Warning: Could not automatically detect CSV delimiter. Assuming comma.")
                csvfile.seek(0)
                reader = csv.DictReader(csvfile)

            if not reader.fieldnames:
                 print(f"Error: CSV file '{csv_filepath}' appears to be empty or has no header row.")
                 return

            required_columns = ['Brand', 'Image']
            missing_columns = [col for col in required_columns if col not in reader.fieldnames]
            if missing_columns:
                print(f"Error: CSV file '{csv_filepath}' is missing required columns: {', '.join(missing_columns)}.")
                print(f"Found columns: {', '.join(reader.fieldnames)}")
                return

            print(f"Starting brand update from {csv_filepath}...")
            updated_count = 0
            not_found_count = 0
            skipped_count = 0
            error_count = 0
            processed_rows = 0
            created_count = 0 # New counter for created brands
            csv_duplicate_count = 0 # New counter for duplicates within the CSV
            processed_brand_names = set() # Keep track of names encountered in the CSV

            for i, row in enumerate(reader, start=1):
                processed_rows = i
                brand_name = row.get('Brand')
                image_path = row.get('Image')

                if not brand_name or not isinstance(brand_name, str) or not brand_name.strip():
                    print(f"Warning: Skipping row {i+1} due to missing or invalid brand name: {row}")
                    skipped_count += 1
                    continue
                if not image_path or not isinstance(image_path, str):
                     print(f"Warning: Skipping row {i+1} due to missing or invalid image path for brand '{brand_name}': {row}")
                     skipped_count += 1
                     continue

                brand_name = brand_name.strip()
                image_path = image_path.strip()

                # Check if this brand name (case-insensitive) has already been processed from the CSV
                if brand_name.lower() in processed_brand_names:
                    print(f"Info: Skipping duplicate brand name found in CSV: '{brand_name}' (Row {i+1})")
                    csv_duplicate_count += 1
                    continue
                else:
                    processed_brand_names.add(brand_name.lower()) # Add to set for future checks

                try:
                    # Case-insensitive lookup for the brand
                    # Use func.lower for database-level lowercasing if supported and indexed, otherwise Python lower()
                    brand = db_session.query(Brand).filter(func.lower(Brand.name) == brand_name.lower()).one_or_none()
                    # Alternative if func.lower causes issues or isn't indexed:
                    # brand = db_session.query(Brand).filter(Brand.name.ilike(brand_name)).one_or_none() # ilike might be slower

                    if brand:
                        current_image_path = str(getattr(brand, 'image', None))
                        if current_image_path != image_path:
                            brand.image = brand_name.lower() + '.jpg'
                            brand.updated_at = func.now()
                            # Session tracks changes, commit happens later
                            print(f"Marked for update: Image for brand '{brand_name}'")
                            updated_count += 1
                        else:
                            # print(f"Skipping brand (image unchanged): '{brand_name}'")
                            skipped_count += 1
                    else:
                        # Brand not found in the database, create it
                        try:
                            print(f"Marked for creation: New brand '{brand_name}'")
                            new_brand = Brand(name=brand_name.title(), image=brand_name.lower() + '.jpg')
                            db_session.add(new_brand)
                            created_count += 1
                        except Exception as create_e:
                            # Handle potential errors during object creation itself (less likely here)
                            print(f"Error preparing brand '{brand_name}' for creation: {create_e} (Row {i+1})")
                            db_session.rollback() # Rollback potential partial adds in this iteration if needed
                            error_count += 1
                        # removed not_found_count += 1

                # one_or_none() handles NoResultFound and MultipleResultsFound implicitly by returning None or raising MultipleResultsFound
                except MultipleResultsFound:
                     # This might occur if func.lower comparison isn't strictly unique or if ilike matches multiple
                     print(f"Error: Multiple brands found matching name '{brand_name}'. Ensure names are unique (case-insensitive). Skipping update. (Row {i+1})")
                     error_count += 1
                except SQLAlchemyError as e:
                    print(f"Database error querying brand '{brand_name}': {e} (Row {i+1})")
                    error_count += 1
                except Exception as e:
                    print(f"Unexpected error processing brand '{brand_name}': {e} (Row {i+1})")
                    error_count += 1

            # Commit changes if any updates or creations were made
            if updated_count > 0 or created_count > 0:
                try:
                    commit_msg = []
                    if updated_count > 0:
                        commit_msg.append(f"{updated_count} updates")
                    if created_count > 0:
                        commit_msg.append(f"{created_count} creations")
                    print(f"\nCommitting {' and '.join(commit_msg)} to the database...")
                    db_session.commit()
                    print("Commit successful.")
                except SQLAlchemyError as e:
                    print(f"Error committing changes to the database: {e}")
                    print("Rolling back transaction.")
                    db_session.rollback()
                    error_count += updated_count + created_count # Count updates and creations as errors if commit failed
                    updated_count = 0
                    created_count = 0
                except Exception as e:
                    print(f"Unexpected error during commit: {e}")
                    db_session.rollback()
                    error_count += updated_count + created_count
                    updated_count = 0
                    created_count = 0
            else:
                 print("No changes detected that require a database commit.")


            print("\n--- Update Summary ---")
            print(f"Processed {processed_rows} rows from CSV.")
            print(f"Successfully updated: {updated_count}")
            print(f"Successfully created: {created_count}") # Added creation count
            print(f"Brands not found (and not created due to error): {not_found_count}") # Clarified meaning
            print(f"Rows skipped (missing data/unchanged/etc.): {skipped_count}")
            print(f"Rows skipped (duplicate brand name in CSV): {csv_duplicate_count}") # Added duplicate count
            print(f"Errors during processing/commit: {error_count}")
            print("----------------------")


    except FileNotFoundError:
        # This case is handled by the initial os.path.exists check, but kept for robustness
        print(f"Error: CSV file not found at {csv_filepath}")
    except Exception as e:
        print(f"An unexpected error occurred while processing the CSV file: {e}")
        if 'db_session' in locals() and db_session.is_active:
             db_session.rollback() # Rollback on unexpected errors during file processing


if __name__ == "__main__":
    # --- Configuration ---
    # !!! IMPORTANT: Set the correct path to your CSV file !!!
    csv_file_path = r'data\brands.csv' # CHANGE THIS
    # Example relative path:
    # csv_file_path = os.path.join(os.path.dirname(__file__), 'brands.csv')

    # --- Basic checks if placeholders need configuration ---
    if 'user:password@host:port/db_name' in DATABASE_URL:
         print("Error: Please update the 'DATABASE_URL' variable in the script with your actual MySQL connection details.")
         sys.exit(1)

    if csv_file_path == 'path/to/your/brands.csv':
         print("Error: Please update the 'csv_file_path' variable in the script with the correct path to your CSV file.")
         sys.exit(1)

    # --- Get a DB session ---
    session = None # Initialize session variable
    try:
        session = SessionLocal()
        print("Database session established.")
        # --- Run the update function ---
        update_brands_from_csv(session, csv_file_path)
    except SQLAlchemyError as e:
        print(f"Failed to establish database session: {e}")
        sys.exit(1)
    except Exception as e:
         print(f"An unexpected error occurred: {e}")
         sys.exit(1)
    finally:
        # --- Clean up session ---
        if session:
            session.close()
            print("Database session closed.")

    print("Script finished.")
