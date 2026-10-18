import { Link } from "react-router-dom";
import { Button } from "../components/common/Button";

export function NotFound() {
  return (
    <div className="notfound">
      <div className="notfound-code">404</div>
      <h1 className="page-title">Page not found</h1>
      <p className="muted">
        The page you are looking for does not exist or has been moved.
      </p>
      <Link to="/">
        <Button variant="primary">Back to dashboard</Button>
      </Link>
    </div>
  );
}
