defmodule RelayAppWeb.Router do
  use RelayAppWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", RelayAppWeb do
    pipe_through :api

    get "/health", HealthController, :show
  end
end
