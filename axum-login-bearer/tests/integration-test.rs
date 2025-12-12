use std::{
    collections::HashMap,
    process::{Child, Command},
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::{
    cookie::{CookieStore, Jar},
    header::{AUTHORIZATION, SET_COOKIE, HeaderMap, HeaderValue},
    Client, StatusCode, Url,
};
use serial_test::serial;

const WEBSERVER_URL: &str = "http://localhost:3000";

#[tokio::test]
#[serial]
async fn sqlite_bearer_example() {
    let _child_guard = start_example_binary("example-sqlite-bearer").await;

    let cookie_jar = Arc::new(Jar::default());
    let client = Client::builder()
        .cookie_provider(cookie_jar.clone())
        .build()
        .unwrap();

    // A logged out user is redirected to the login URL with a next query
    //string.
    let res = client.get(url("/")).send().await.unwrap();
    assert_eq!(*res.url(), url("/login?next=%2F"));
    assert_eq!(res.status(), StatusCode::OK);

    assert!(
        cookie_jar.cookies(&url("/")).is_none(),
        "Expected 'id' cookie to not be set after failed login"
    );

    // Log in with invalid credentials.
    let res = login(&client, "ferris", "bogus").await;
    assert_eq!(*res.url(), url("/login"));
    assert_eq!(res.status(), StatusCode::OK);

    let cookies = cookie_jar
        .cookies(&url("/"))
        .expect("A cookie should be set");
    assert!(
        cookies.to_str().unwrap_or("").contains("id="),
        "Expected 'id' cookie to be set after login"
    );

    // Log in with valid credentials.
    let res = login(&client, "ferris", "hunter42").await;
    assert_eq!(*res.url(), url("/"));
    assert_eq!(res.status(), StatusCode::OK);

    // Extract the cookie from the successful login as if it's the session id
    let cookies = cookie_jar
        .cookies(&url("/"))
        .expect("A cookie should be set");
    let (_, session_id) = cookies.to_str()
        .unwrap()
        .split_once('=')
        .expect("token should have been provided as a cookie");

    // Attempt to use that cookie set after the successful login as the bearer token
    let bearer_client = client_with_bearer_token(&session_id);

    // Unfortunately, it will not work as the cookie is encrypted using a different scheme.
    let res = bearer_client.get(url("/")).send().await.unwrap();
    assert_eq!(*res.url(), url("/login?next=%2F"));
    assert_eq!(res.status(), StatusCode::OK);

    let simple_client = Client::new();
    // Instead, use the dedicated endpoint that provide the bearer token.  First validate the
    // endpoint works (but with invalid credentials for first try, then valid ones after)
    let res = get_bearer_token(&simple_client, "ferris", "bogus").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(!res.headers().contains_key(SET_COOKIE));

    // Now with a proper bearer token, it should work.
    let res = get_bearer_token(&simple_client, "ferris", "hunter42").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!res.headers().contains_key(SET_COOKIE));
    let bearer_client = client_with_bearer_token(&res.text().await.unwrap());
    let res = bearer_client.get(url("/")).send().await.unwrap();
    assert_eq!(*res.url(), url("/"));
    assert_eq!(res.status(), StatusCode::OK);
    // TODO naturally should configure the bearer token issuer with some encryption scheme

    // Log out and check the cookie has been removed in response.
    let res = client.get(url("/logout")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        cookie_jar.cookies(&url("/")).iter().len(),
        0,
        "Expected 'id' cookie to be removed"
    );

    // The bearer token should also be invalidated if it use the logout endpoint.
    let res = bearer_client.get(url("/logout")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = bearer_client.get(url("/")).send().await.unwrap();
    assert_eq!(*res.url(), url("/login?next=%2F"));
    assert_eq!(res.status(), StatusCode::OK);
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.child.kill().expect("Failed to kill example binary");
        self.child
            .wait()
            .expect("Failed to wait for example binary to exit");
    }
}

async fn start_example_binary(binary_name: &str) -> ChildGuard {
    let child = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg(binary_name)
        .spawn()
        .expect("Failed to start example binary");

    let start_time = Instant::now();
    let mut is_server_ready = false;

    while start_time.elapsed() < Duration::from_secs(300) {
        if reqwest::get(WEBSERVER_URL).await.is_ok() {
            is_server_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    if !is_server_ready {
        panic!("The web server did not become ready within the expected time.");
    }

    ChildGuard { child }
}

fn url(path: &str) -> Url {
    let formatted_url = if path.starts_with('/') {
        format!("{WEBSERVER_URL}{path}")
    } else {
        format!("{WEBSERVER_URL}/{path}")
    };
    formatted_url.parse().unwrap()
}

async fn login(client: &Client, username: &str, password: &str) -> reqwest::Response {
    let mut form = HashMap::new();
    form.insert("username", username);
    form.insert("password", password);
    client.post(url("/login")).form(&form).send().await.unwrap()
}

fn client_with_bearer_token(bearer_token: &str) -> Client {
    let mut bearer_token = HeaderValue::from_str(&format!("Bearer {bearer_token}")).unwrap();
    bearer_token.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, bearer_token);
    Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

async fn get_bearer_token(client: &Client, username: &str, password: &str) -> reqwest::Response {
    let mut form = HashMap::new();
    form.insert("username", username);
    form.insert("password", password);
    client.post(url("/api/bearer")).form(&form).send().await.unwrap()
}
