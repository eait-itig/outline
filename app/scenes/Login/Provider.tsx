import { EmailIcon } from "outline-icons";
import * as React from "react";
import { TFunction, withTranslation } from "react-i18next";

import styled from "styled-components";
import AuthLogo from "components/AuthLogo";
import ButtonLarge from "components/ButtonLarge";
import InputLarge from "components/InputLarge";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'utils/ApiClient' or its corres... Remove this comment to see the full error message
import { client } from "utils/ApiClient";

type Props = {
  id: string;
  name: string;
  authUrl: string;
  isCreate: boolean;
  onEmailSuccess: (email: string) => void;
  t: TFunction;
};
type State = {
  showEmailSignin: boolean;
  isSubmitting: boolean;
  email: string;
};

class Provider extends React.Component<Props, State> {
  state = {
    showEmailSignin: false,
    isSubmitting: false,
    email: "",
  };

  handleChangeEmail = (event: React.SyntheticEvent<HTMLInputElement>) => {
    this.setState({
      // @ts-expect-error ts-migrate(2339) FIXME: Property 'value' does not exist on type 'EventTarg... Remove this comment to see the full error message
      email: event.target.value,
    });
  };

  handleSubmitEmail = async (event: React.SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (this.state.showEmailSignin && this.state.email) {
      this.setState({
        isSubmitting: true,
      });

      try {
        const response = await client.post(event.currentTarget.action, {
          email: this.state.email,
        });

        if (response.redirect) {
          window.location.href = response.redirect;
        } else {
          this.props.onEmailSuccess(this.state.email);
        }
      } finally {
        this.setState({
          isSubmitting: false,
        });
      }
    } else {
      this.setState({
        showEmailSignin: true,
      });
    }
  };

  render() {
    const { isCreate, id, name, authUrl, t } = this.props;

    if (id === "email") {
      if (isCreate) {
        return null;
      }

      return (
        <Wrapper key="email">
          <Form
            method="POST"
            action="/auth/email"
            onSubmit={this.handleSubmitEmail}
          >
            {this.state.showEmailSignin ? (
              <>
                <InputLarge
                  type="email"
                  name="email"
                  placeholder="me@domain.com"
                  value={this.state.email}
                  onChange={this.handleChangeEmail}
                  disabled={this.state.isSubmitting}
                  autoFocus
                  required
                  short
                />
                // @ts-expect-error ts-migrate(2746) FIXME: This JSX tag's
                'children' prop expects a single ch... Remove this comment to
                see the full error message
                <ButtonLarge type="submit" disabled={this.state.isSubmitting}>
                  {t("Sign In")} →
                </ButtonLarge>
              </>
            ) : (
              // @ts-expect-error ts-migrate(2769) FIXME: No overload matches this call.
              <ButtonLarge type="submit" icon={<EmailIcon />} fullwidth>
                {t("Continue with Email")}
              </ButtonLarge>
            )}
          </Form>
        </Wrapper>
      );
    }

    return (
      <Wrapper key={id}>
        <ButtonLarge
          // @ts-expect-error ts-migrate(2769) FIXME: No overload matches this call.
          onClick={() => (window.location.href = authUrl)}
          icon={<AuthLogo providerName={id} />}
          fullwidth
        >
          {t("Continue with {{ authProviderName }}", {
            authProviderName: name,
          })}
        </ButtonLarge>
      </Wrapper>
    );
  }
}

const Wrapper = styled.div`
  margin-bottom: 1em;
  width: 100%;
`;
const Form = styled.form`
  width: 100%;
  display: flex;
  justify-content: space-between;
`;

// @ts-expect-error ts-migrate(2344) FIXME: Type 'Provider' does not satisfy the constraint 'C... Remove this comment to see the full error message
export default withTranslation()<Provider>(Provider);