var ErrDidNotWork = errors.New("did not work")

func DoTheThing(reallyDoIt bool) (err error) {
  if reallyDoIt {
    result, err := tryTheThing()
    if err != nil || result != "it worked" {
      err = ErrDidNotWork
    }
  }
  return err
}