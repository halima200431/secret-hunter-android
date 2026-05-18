# Secret Hunter - Android Security Analysis Tool

A comprehensive security analysis tool for Android APK files that detects secrets, vulnerabilities, risky endpoints, and generates detailed security reports.

## 🎯 Features

- **APK Analysis**: Extract and analyze Android APK files
- **Secret Detection**: Identify exposed secrets, API keys, and sensitive credentials
- **Endpoint Scanning**: Detect and analyze API endpoints with risk assessment
- **Manifest Analysis**: Extract and analyze AndroidManifest.xml
- **Network Analysis**: Analyze network configurations and connections
- **Risk Scoring**: Comprehensive risk assessment with scoring algorithm
- **AI-Powered Analysis**: Advanced analysis using AI models
- **Report Generation**: Generate detailed HTML reports with findings
- **Web Dashboard**: Interactive React-based frontend for analysis results
- **RESTful API**: Complete API for programmatic access

## 📋 Tech Stack

### Backend
- **Framework**: Flask (Python)
- **Analysis Tools**: APK extraction, manifest parsing, network analysis
- **Database**: File-based storage system
- **API**: RESTful endpoints for analysis, reports, and health checks
- **AI**: Integration with AI models for enhanced analysis

### Frontend
- **Framework**: React with Vite
- **Styling**: Tailwind CSS + PostCSS
- **Components**: Modular component architecture
- **Features**: Dashboard, file upload, analysis visualization, report generation

### DevOps
- **Containerization**: Docker & Docker Compose
- **Environment Management**: Multi-environment support

## 📁 Project Structure

```
secret-hunter-android/
├── backend/                 # Flask backend application
│   ├── api/                # API routes (analysis, reports, health)
│   ├── core/               # Core utilities (config, logging, exceptions)
│   ├── jobs/               # Job management system
│   ├── reports/            # Report generation
│   ├── rules/              # Security rules and patterns (JSON)
│   ├── scanners/           # Security scanners
│   │   ├── apk_extractor.py
│   │   ├── secret_scanner.py
│   │   ├── endpoint_scanner.py
│   │   ├── manifest_analyzer.py
│   │   └── risk_scoring.py
│   ├── schemas/            # Data validation schemas
│   ├── services/           # Business logic services
│   ├── storage/            # Data persistence
│   └── tests/              # Unit tests
├── frontend/               # React + Vite application
│   ├── src/
│   │   ├── components/     # Reusable React components
│   │   ├── pages/          # Page components
│   │   ├── api/            # API client
│   │   └── utils/          # Utility functions
│   └── public/
├── docs/                   # Documentation
├── scripts/                # Setup and utility scripts
├── uploads/                # Temporary upload directory
├── logs/                   # Application logs
└── reports/                # Generated reports
```

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Node.js 16+
- Docker & Docker Compose (optional)
- APKTool (for APK extraction)

### Installation

#### 1. Backend Setup

```bash
cd backend
pip install -r requirements.txt
```

#### 2. Frontend Setup

```bash
cd frontend
npm install
```

#### 3. Configuration

Update configuration in `backend/core/config.py`:
```python
UPLOAD_FOLDER = "uploads"
RULES_FOLDER = "rules"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
```

### Running Locally

#### Start Backend
```powershell
# Using PowerShell script
./scripts/run_backend.ps1

# Or manually
cd backend
python app.py
```

Backend runs on `http://localhost:5000`

#### Start Frontend
```powershell
# Using PowerShell script
./scripts/run_frontend.ps1

# Or manually
cd frontend
npm run dev
```

Frontend runs on `http://localhost:5173`

### Running with Docker

```bash
docker-compose up --build
```

This will start:
- Backend API: `http://localhost:5000`
- Frontend: `http://localhost:3000`

## 📖 API Endpoints

### Analysis
- `POST /api/analysis/upload` - Upload and analyze APK file
- `GET /api/analysis/<analysis_id>` - Get analysis results
- `POST /api/analysis/advanced` - Advanced analysis with AI

### Reports
- `GET /api/reports/<analysis_id>` - Generate report
- `POST /api/reports/export` - Export report as PDF/HTML

### Health
- `GET /api/health` - Health check endpoint

## 🔍 Scanning Rules

Security rules are defined in `backend/rules/`:
- `secret_patterns.json` - Patterns for detecting secrets
- `endpoint_patterns.json` - API endpoint patterns
- `risk_rules.json` - Risk assessment rules

## 📊 Analysis Results

Analysis results include:
- **Secrets Found**: Detected API keys, tokens, credentials
- **Endpoints**: Discovered API endpoints with risk levels
- **Permissions**: AndroidManifest permissions analysis
- **Network**: Network configuration analysis
- **Risk Score**: Overall security risk assessment
- **Recommendations**: Security improvement suggestions

## 🧪 Testing

Run backend tests:
```bash
cd backend
python -m pytest tests/
```

## 📝 Configuration Files

- `backend/core/config.py` - Application configuration
- `backend/rules/*.json` - Security scanning rules
- `frontend/vite.config.js` - Frontend build configuration
- `docker-compose.yml` - Docker services configuration

## 🔐 Security Considerations

- Sensitive data is masked in reports
- Uploaded files are stored temporarily
- Analysis results are sanitized
- Configure appropriate access controls
- Use HTTPS in production

## 📄 License

This project is provided as-is for security research and educational purposes.

## 🤝 Contributing

Contributions are welcome! Please follow the existing code structure and testing practices.

## 📞 Support

For issues and questions:
1. Check the [documentation](docs/)
2. Review existing issues
3. Create a new issue with detailed information

## 🗺️ Roadmap

- [ ] Cloud deployment support
- [ ] Mobile app integration
- [ ] Real-time scanning
- [ ] Advanced ML-based detection
- [ ] Community rule sharing
- [ ] API rate limiting
- [ ] User authentication system

---

**Last Updated**: May 2026

