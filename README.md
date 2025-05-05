# LogIQ API

A FastAPI-based service for processing questions.

## Setup

1. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python -m app.main
   ```

## API Endpoints

### Process Question

**URL:** `/api/question`

**Method:** `POST`

**Request Body:**

```json
{
  "intcid": "customer internal id",
  "tid": "triage record/facet id",
  "question": "question?",
  "qid": "question id"
}
```

**Response:**

```json
{
    "success": true,
    "data": {
        "type": "boolean/text",
        "answer": true/false or "text response",
        "description": "text explaining answer"
    }
}
```

### Status Check

The status endpoint is available at both paths for convenience:

**URLs:**

- `/status` (root path)
- `/api/status` (through API router)

**Method:** `GET`

**Response:**

```json
{
  "status": "Ok",
  "message": "Service is running"
}
```
