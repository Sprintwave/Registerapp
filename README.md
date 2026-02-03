# Care Register

A minimal digital register for care organisations to track patient arrivals and departures.

## Features

- **Carer Interface**: Simple mobile-friendly form to log patient arrivals/departures
- **Admin Dashboard**: View currently on-site patients and full event log
- **CSV Export**: Export filtered event data
- **Role-based Access**: Admin and carer roles with different permissions
- **Mobile Optimized**: Touch-friendly interface for smartphone use

## Quick Start

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Installation

1. **Clone or download this project**
   ```bash
   cd care-register
   ```

2. **Create and activate a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open your browser**
   ```
   http://127.0.0.1:5000
   ```

### Demo Accounts

The app comes with pre-seeded demo accounts:

**Admin**: 
- Username: `admin`, Password: `admin123`

**Carers**: 
- `sarah_jones` / `carer123` (Sunrise Care Center)
- `mike_davis` / `carer123` (Meadowbrook Facility)  
- `emma_wilson` / `carer123` (Riverside Day Care)
- `james_taylor` / `carer123` (Garden View Center)
- `lisa_brown` / `carer123` (Harmony House)

### Sample Data

The application includes:
- **5 Care Locations** with unique addresses
- **30 Patients** (6 per location)
- **5 Carers** (1 per location)
- Each patient is assigned to their location's primary carer

**Locations:**
- Sunrise Care Center - 123 Oak Street, Downtown
- Meadowbrook Facility - 456 Pine Avenue, Westside  
- Riverside Day Care - 789 River Road, Northbank
- Garden View Center - 321 Elm Drive, Southside
- Harmony House - 654 Maple Lane, Eastend

## Usage

### For Carers

1. Login with carer credentials
2. Navigate to the register page (`/register`)
3. Select a patient and event type (ARRIVED/LEFT)
4. If logging a departure, select who they left with and transport mode
5. Add optional notes
6. Submit to save the event

**Mobile Use**: Carers can save the `/register` page as a home screen bookmark on their phones for quick access.

### For Admins

1. Login with admin credentials
2. View the enhanced dashboard showing:
   - **Location Statistics**: Occupancy rates and patient counts per location
   - **Daily Activity Chart**: Visual graph of arrivals vs departures over time
   - **Currently On-Site Patients**: Organized by location with carer assignments
   - **Event Log**: Filterable by date, location, and patient name
   - **CSV Export**: Export filtered data for reporting

## Database

Uses SQLite with the following tables:
- `locations`: Care facility locations with addresses
- `users`: Login credentials, roles, and location assignments
- `patients`: Patient information with location and primary carer assignments
- `events`: Arrival/departure events with timestamps and details

The database file (`care_register.db`) is created automatically on first run with comprehensive seed data.

## Security Notes

⚠️ **This is a proof-of-concept application**

For production use, consider:
- Change the secret key in `app.py`
- Use environment variables for configuration
- Add HTTPS/SSL
- Implement proper password policies
- Add user management features
- Consider using a production database (PostgreSQL, MySQL)

## Project Structure

```
care-register/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
│   ├── base.html      # Base template with Bootstrap
│   ├── login.html     # Login form
│   ├── register.html  # Carer event registration
│   └── admin.html     # Admin dashboard
└── README.md          # This file
```

## Development

To modify the application:

1. **Add new patients**: Insert directly into the database or add via the admin interface (future enhancement)
2. **Modify event types**: Update the CHECK constraints in the database schema
3. **Add new fields**: Modify the database schema and update templates
4. **Styling**: Edit the CSS in `templates/base.html` or add external stylesheets

## License

This project is provided as-is for educational and demonstration purposes.
# Registerapp
